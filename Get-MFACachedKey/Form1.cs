using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;

namespace getSAMLResponse
{
    public partial class Form1 : Form
    {
        public string idpURL {  get; set; }
        public string samlResponse {  get; set; }
        public Form1(string URL)
        {
            this.idpURL = URL;
            this.samlResponse = string.Empty;
            InitializeComponent();
            webView.CoreWebView2InitializationCompleted += WebView_CoreWebView2InitializationCompleted;
            InitializeAsync();
        }

        void WebView_CoreWebView2InitializationCompleted(object sender, CoreWebView2InitializationCompletedEventArgs e)
        {
            //Secure browser to prevent dev tools, right click, shortcut keys, swiping back and forth and autofill.
            webView.CoreWebView2.Settings.AreDefaultContextMenusEnabled = false;
            webView.CoreWebView2.Settings.AreBrowserAcceleratorKeysEnabled = false;
            webView.CoreWebView2.Settings.AreDevToolsEnabled = false;
            webView.CoreWebView2.Settings.IsPasswordAutosaveEnabled = false;
            webView.CoreWebView2.Settings.IsSwipeNavigationEnabled = false;
            webView.CoreWebView2.Settings.IsGeneralAutofillEnabled = false;
        }
        
        //wait for a specific URL to be true based on the filter. In CyberArk example, there is a post to either api/auth/saml/logon or /auth/saml, both should match successfully.
        async void InitializeAsync()
        {
            // Force CoreWebView2 to be created.
            await webView.EnsureCoreWebView2Async(null);

            // Create the filter to be used in the WebResourceRequested event.
            string filter = "*auth/saml*";

            // Assign the filter.
            webView.CoreWebView2.AddWebResourceRequestedFilter(filter, CoreWebView2WebResourceContext.Document);

            // Create the event trigger.
            webView.CoreWebView2.WebResourceRequested += CoreWebView2_WebResourceRequested;

            // Navigate to the URL.
            webView.CoreWebView2.Navigate(this.idpURL);
        }

        //Get the content of the post request, stop navigation, decode the content and check that it matches Regex for a response. If does exit app.
        private void CoreWebView2_WebResourceRequested(object sender, CoreWebView2WebResourceRequestedEventArgs e)
        {
            string postData = null;
            var content = e.Request.Content;

            if (content != null)
            {
                using (var ms = new MemoryStream())
                {
                    content.CopyTo(ms);
                    postData = Encoding.UTF8.GetString(ms.ToArray());
                    postData = HttpUtility.HtmlDecode(postData);
                }
                webView.NavigationStarting += StopNavigation;
                string decodedSAML = HttpUtility.UrlDecode(postData);
                int indexOfPostData = decodedSAML.IndexOf("&RelayState");
                if (indexOfPostData >= 0)
                    decodedSAML = decodedSAML.Remove(indexOfPostData);


                if (decodedSAML != null)
                {
                    string regexPatern = @"(?<=SAMLResponse=)(?s)(.*)";
                    Match m = Regex.Match(decodedSAML, regexPatern, RegexOptions.IgnoreCase);
                    if (m.Success)
                    {
                        // Return the SAML Response
                        this.samlResponse = m.Value;

                        //Console.Out.WriteLine(m.Value);
                        Application.Exit();
                    }
                    else
                    {
                        throw new InvalidOperationException("Unable to match SAML Response to regex.");
                    }

                }
            }
            else
            {
                throw new InvalidOperationException("Unable to find SAML Response content");
            }

        }

        //Stop webview from continuing navigation.
        void StopNavigation(object sender, CoreWebView2NavigationStartingEventArgs args)
        {
            args.Cancel = true;
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }
    }
}
