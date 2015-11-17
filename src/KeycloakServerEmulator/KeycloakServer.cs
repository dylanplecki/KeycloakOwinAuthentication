using System;
using System.Net;
using System.Net.Sockets;
using Unosquare.Labs.EmbedIO;

namespace KeycloakServerEmulator
{
    public class KeycloakServer
    {
        public KeycloakServer(Uri baseUri = null)
        {
            if (baseUri == null)
            {
                // Find best address for new URI
                baseUri = new UriBuilder
                {
                    Scheme = "https",
                    Host = "localhost",
                    Path = "/auth",
                    Port = FindFreeTcpPort()
                }.Uri;
            }

            var server = WebServer
                .Create(baseUri.ToString())
                .EnableCors()
                .WithLocalSession();
            server.RunAsync();
        }

        private static int FindFreeTcpPort()
        {
            var l = new TcpListener(IPAddress.Loopback, 0);
            l.Start();
            var port = ((IPEndPoint)l.LocalEndpoint).Port;
            l.Stop();
            return port;
        }
    }
}
