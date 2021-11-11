﻿using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using SharpHound3.Enums;
using SearchOption = System.DirectoryServices.Protocols.SearchOption;

namespace SharpHound3
{
    /// <summary>
    /// Class encapsulating LDAP searching
    /// </summary>
    internal class DirectorySearch
    {
        private readonly string _domainController;
        private readonly string _domainName;
        private readonly Domain _domain;
        private Dictionary<string, string> _domainGuidMap;
        private bool _isFaulted;

        private readonly string baseLdapPath;
        //Thread-safe storage for our Ldap Connection Pool
        private readonly ConcurrentBag<LdapConnection> _connectionPool = new ConcurrentBag<LdapConnection>();

        public DirectorySearch(string domainName = null, string domainController = null)
        {
            _domain = GetDomain();
            _domainName = Helpers.NormalizeDomainName(domainName);
            baseLdapPath = $"DC={_domainName.Replace(".", ",DC=")}";
            _domainController = Options.Instance.DomainController ?? domainController;
            _domainGuidMap = new Dictionary<string, string>();
            CreateSchemaMap();
        }

        //Look up a username in the Global Catalog to get a list of potential domains a session can come from
        internal async Task<string[]> LookupUserInGC(string username)
        {
            if (Cache.Instance.GetGlobalCatalogMatches(username, out var sids))
                return sids;

            var connection = GetGlobalCatalogConnection();

            try
            {
                //Create a search request looking for users with the specified samaccountname, only getting back the sid
                var searchRequest = CreateSearchRequest($"(&(samAccountType=805306368)(samaccountname={username}))",
                    SearchScope.Subtree, new[] { "objectsid" });

                var iAsyncResult = connection.BeginSendRequest(searchRequest,
                    PartialResultProcessing.NoPartialResultSupport, null, null);

                var task = Task<SearchResponse>.Factory.FromAsync(iAsyncResult,
                    x => (SearchResponse)connection.EndSendRequest(x));

                try
                {
                    var response = await task;

                    if (response == null)
                    {
                        sids = new string[0];
                        Cache.Instance.Add(username, sids);
                        return sids;
                    }

                    sids = response.Entries.Cast<SearchResultEntry>().Select(entry => entry.GetSid()).Where(sid => sid != null).ToArray();
                    Cache.Instance.Add(username, sids);
                    return sids;

                }
                catch
                {
                    return null;
                }
            }
            catch (LdapException)
            {
                return null;
            }
            finally
            {
                //Always dispose GC connections
                connection.Dispose();
            }
        }

        /// <summary>
        /// Get a single LDAP entry for the specified filter
        /// </summary>
        /// <param name="ldapFilter">Ldap Filter to search for</param>
        /// <param name="props">Properties to request</param>
        /// <param name="scope">Scope to search</param>
        /// <param name="adsPath">Distinguished name to bind too</param>
        /// <param name="globalCatalog">Use the global catalog instead of the regular directory</param>
        /// <returns>The LDAP search result entry for the specified filter or null if nothing was found</returns>
        internal async Task<SearchResultEntry> GetOne(string ldapFilter, string[] props, SearchScope scope, string adsPath = null, bool globalCatalog = false)
        {
            var connection = globalCatalog ? GetGlobalCatalogConnection() : GetLdapConnection();
            try
            {
                var searchRequest = CreateSearchRequest(ldapFilter, scope, props, adsPath);

                //Asynchronously send the search request
                var iAsyncResult = connection.BeginSendRequest(searchRequest,
                    PartialResultProcessing.NoPartialResultSupport, null, null);

                var task = Task<SearchResponse>.Factory.FromAsync(iAsyncResult,
                    x => (SearchResponse)connection.EndSendRequest(x));


                //Wait for the search request to finish
                var response = await task;

                //Check if theres entries
                if (response.Entries.Count == 0)
                    return null;

                //Return the first search result entry
                return response.Entries[0];
            }
            catch
            {
                return null;
            }
            finally
            {
                //Dispose the global catalog connection or add the connection back to the connection pool
                if (!globalCatalog)
                    _connectionPool.Add(connection);
                else
                    connection.Dispose();
            }
        }

        /// <summary>
        /// Performs an LDAP search returning multiple objects/pages
        /// </summary>
        /// <param name="ldapFilter"></param>
        /// <param name="props"></param>
        /// <param name="scope"></param>
        /// <param name="adsPath"></param>
        /// <param name="globalCatalog"></param>
        /// <returns>An IEnumerable with search results</returns>
        internal IEnumerable<SearchResultEntry> QueryLdap(string ldapFilter, string[] props, SearchScope scope, string adsPath = null, bool globalCatalog = false)
        {
            var connection = globalCatalog ? GetGlobalCatalogConnection() : GetLdapConnection();
            try
            {
                var searchRequest = CreateSearchRequest(ldapFilter, scope, props, adsPath);
                var pageRequest = new PageResultRequestControl(500);
                searchRequest.Controls.Add(pageRequest);

                if (Options.Instance.ResolvedCollectionMethods.HasFlag(CollectionMethodResolved.ACL))
                {
                    var securityDescriptorFlagControl = new SecurityDescriptorFlagControl
                    {
                        SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner
                    };
                    searchRequest.Controls.Add(securityDescriptorFlagControl);
                }

                while (true)
                {
                    SearchResponse searchResponse;
                    try
                    {
                        searchResponse = (SearchResponse)connection.SendRequest(searchRequest);
                    }
                    catch (Exception e)
                    {
                        //Console.WriteLine(ldapFilter);
                        //Console.WriteLine("\nUnexpected exception occured:\n\t{0}: {1}",
                        //    e.GetType().Name, e.Message);
                        yield break;
                    }

                    if (searchResponse.Controls.Length != 1 ||
                        !(searchResponse.Controls[0] is PageResultResponseControl))
                    {
                        Console.WriteLine("Server does not support paging");
                        yield break;
                    }

                    var pageResponse = (PageResultResponseControl)searchResponse.Controls[0];

                    foreach (SearchResultEntry entry in searchResponse.Entries)
                    {
                        yield return entry;
                    }

                    if (pageResponse.Cookie.Length == 0)
                        break;

                    pageRequest.Cookie = pageResponse.Cookie;
                }
            }
            finally
            {
                if (!globalCatalog)
                    _connectionPool.Add(connection);
                else
                    connection.Dispose();
            }
        }

        /// <summary>
        /// Use ranged retrieval to grab large attributes (generally the member attribute)
        /// </summary>
        /// <param name="distinguishedName">DN of object to retrieve from</param>
        /// <param name="attribute">Attribute name to retrieve values for</param>
        /// <returns>List of all values of the attribute</returns>
        internal async Task<List<string>> RangedRetrievalAsync(string distinguishedName, string attribute)
        {
            var connection = GetLdapConnection();
            var values = new List<string>();
            try
            {
                //Set up our variables for paging
                var index = 0;
                var step = 0;
                var baseString = $"{attribute}";
                var currentRange = $"{baseString};range={index}-*";
                //Example search string: member;range=0-1000
                var searchDone = false;

                //Create our request and add our range search to the properties attribute. Set the search base to the DN of the object
                var searchRequest = CreateSearchRequest($"{attribute}=*", SearchScope.Base, new[] { currentRange },
                    distinguishedName);

                //Set up a continuous loop, which ends when we run out of attributes to retrieve
                while (true)
                {
                    //Asynchronously send our search request
                    var iASyncResult = connection.BeginSendRequest(searchRequest,
                        PartialResultProcessing.NoPartialResultSupport, null, null);
                    var task = Task<SearchResponse>.Factory.FromAsync(iASyncResult, x => (SearchResponse)connection.EndSendRequest(x));

                    //Wait for the request to finish
                    var response = await task;

                    //There should only be one SearchResultEntry
                    if (response?.Entries.Count == 1)
                    {
                        var entry = response.Entries[0];
                        //We should only ever have one attribute, since thats all we requested
                        foreach (string attr in entry.Attributes.AttributeNames)
                        {
                            //Set our current range to the attribute name
                            currentRange = attr;
                            //Check if the string has the * character in it. If it does, we've reached the end of our search
                            searchDone = currentRange.IndexOf("*", 0, StringComparison.Ordinal) > 0;
                            //Set our step to the number of attributes that came back
                            step = entry.Attributes[currentRange].Count;
                        }

                        // Grab all the values of the attribute
                        foreach (string member in entry.Attributes[currentRange].GetValues(typeof(string)))
                        {
                            values.Add(member);
                            index++;
                        }

                        //If we're done, return the values and exit the loop
                        if (searchDone)
                            return values;

                        // Theres more to retrieve, so update our search string, and then do the search again to get the next range
                        currentRange = $"{baseString};range={index}-{index + step}";

                        searchRequest.Attributes.Clear();
                        searchRequest.Attributes.Add(currentRange);
                    }
                    else
                    {
                        return values;
                    }
                }
            }
            finally
            {
                //Add the ldap connection back to the pool
                _connectionPool.Add(connection);
            }
        }

        /// <summary>
        /// Get the name of a schema attribute by its GUID
        /// </summary>
        /// <param name="guid"></param>
        /// <param name="name"></param>
        /// <returns></returns>
        internal bool GetAttributeFromGuid(string guid, out string name)
        {
            return _domainGuidMap.TryGetValue(guid, out name);
        }

        /// <summary>
        /// Gets the domain object associated with the specified domain for this DirectorySearcher
        /// </summary>
        /// <returns></returns>
        private Domain GetDomain()
        {
            try
            {
                if (_domainName == null)
                    return Domain.GetCurrentDomain();

                var context = new DirectoryContext(DirectoryContextType.Domain, _domainName);
                return Domain.GetDomain(context);
            }
            catch
            {
                _isFaulted = true;
                return null;
            }
        }

        /// <summary>
        /// Gets an LDAPConnection to the Global Catalog
        /// </summary>
        /// <returns></returns>
        private LdapConnection GetGlobalCatalogConnection()
        {
            //Use the domain controller 
            var domainController = _domainController ?? _domainName;

            var identifier = new LdapDirectoryIdentifier(domainController, 3268);
            var connection = Options.Instance.LdapUsername != null ? new LdapConnection(identifier, new NetworkCredential(Options.Instance.LdapUsername, Options.Instance.LdapPassword)) : new LdapConnection(identifier);

            var ldapSessionOptions = connection.SessionOptions;
            if (!Options.Instance.DisableKerberosSigning)
            {
                ldapSessionOptions.Signing = true;
                ldapSessionOptions.Sealing = true;
            }

            ldapSessionOptions.ProtocolVersion = 3;
            ldapSessionOptions.ReferralChasing = ReferralChasingOptions.None;

            connection.Timeout = new TimeSpan(0, 5, 0);
            return connection;
        }

        private LdapConnection GetLdapConnection()
        {
            if (_connectionPool.TryTake(out var connection))
            {
                return connection;
            }

            var domainController = _domainController ?? _domainName;
            var port = Options.Instance.LdapPort == 0
                ? (Options.Instance.SecureLDAP ? 636 : 389)
                : Options.Instance.LdapPort;
            var identifier = new LdapDirectoryIdentifier(domainController, port, false, false);

            connection = Options.Instance.LdapUsername != null ? new LdapConnection(identifier, new NetworkCredential(Options.Instance.LdapUsername, Options.Instance.LdapPassword)) : new LdapConnection(identifier);

            var ldapSessionOptions = connection.SessionOptions;
            if (!Options.Instance.DisableKerberosSigning)
            {
                ldapSessionOptions.Signing = true;
                ldapSessionOptions.Sealing = true;
            }

            ldapSessionOptions.ProtocolVersion = 3;
            ldapSessionOptions.ReferralChasing = ReferralChasingOptions.None;
            ldapSessionOptions.SendTimeout = new TimeSpan(0,0,10,0);

            connection.Timeout = new TimeSpan(0,0, 10, 0);
            return connection;
        }

        private SearchRequest CreateSearchRequest(string ldapFilter, SearchScope scope, string[] props, string adsPath = null)
        {
            var activeDirectorySearchPath = adsPath ?? baseLdapPath;
            var request = new SearchRequest(activeDirectorySearchPath, ldapFilter, scope, props);
            request.Controls.Add(new SearchOptionsControl(SearchOption.DomainScope));

            return request;
        }

        private void CreateSchemaMap()
        {
            var map = new Dictionary<string, string>();
            if (_isFaulted)
                return;

            // AD Schema is defined at forest-level so we use forest DN as LDAP search base
            var path = _domain.Forest.Schema.Name;
            Console.WriteLine($"[+] Creating Schema map for domain {_domainName} using path {path}");

            foreach (var result in QueryLdap("(schemaIDGUID=*)", new[] { "schemaidguid", "name" }, SearchScope.Subtree, path))
            {
                var name = result.GetProperty("name");
                var guid = new Guid(result.GetPropertyAsBytes("schemaidguid")).ToString();
                try
                {
                    map.Add(guid, name);
                }
                catch
                {
                    //pass
                }
                
            }

            _domainGuidMap = map;
        }

        ~DirectorySearch()
        {
            foreach (var connection in _connectionPool)
            {
                connection.Dispose();
            }
        }
    }
}
