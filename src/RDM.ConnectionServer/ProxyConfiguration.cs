using System.Net;
using Microsoft.AspNetCore.HttpOverrides;
namespace RDM.ConnectionServer;
public static class ProxyConfiguration
{
    // Opt-in only. Never accept forwarded headers from arbitrary Internet peers.
    public static ForwardedHeadersOptions? Create(IConfiguration configuration)
    {
        string? networks=configuration["RDM_TRUSTED_PROXY_NETWORKS"];
        if(string.IsNullOrWhiteSpace(networks))return null;
        var options=new ForwardedHeadersOptions {ForwardedHeaders=ForwardedHeaders.XForwardedFor|ForwardedHeaders.XForwardedProto,ForwardLimit=1};
        options.KnownIPNetworks.Clear();options.KnownProxies.Clear();
        foreach(string text in networks.Split(';',StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries))
        {
            if(!System.Net.IPNetwork.TryParse(text,out var network)||network.PrefixLength==0)throw new InvalidOperationException("RDM_TRUSTED_PROXY_NETWORKS must contain explicit non-global CIDRs.");
            options.KnownIPNetworks.Add(network);
        }
        if(options.KnownIPNetworks.Count==0)throw new InvalidOperationException("Empty proxy allowlist.");
        return options;
    }
}
