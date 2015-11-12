using System;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Threading.Tasks;
using KeycloakIdentityModel.Models.Configuration;

namespace KeycloakIdentityModel.Models.Messages
{
    public abstract class GenericMessage<T>
    {
        protected GenericMessage(IKeycloakParameters options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));

            Options = options;
        }

        protected IKeycloakParameters Options { get; }
        public abstract Task<T> ExecuteAsync();

        protected async Task<HttpResponseMessage> SendHttpPostRequest(Uri uri, HttpContent content = null)
        {
            HttpResponseMessage response;
            try
            {
                var client = new HttpClient();
                response = await client.PostAsync(uri, content);
            }
            catch (Exception exception)
            {
                throw new Exception("HTTP client URI is inaccessible", exception);
            }

            // Check for HTTP errors
            if (response.StatusCode == HttpStatusCode.BadRequest)
                throw new AuthenticationException(); // Assume bad credentials
            if (!response.IsSuccessStatusCode)
                throw new Exception("HTTP client returned an unrecoverable error");

            return response;
        }
    }
}