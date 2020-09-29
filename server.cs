using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.IO;

namespace HttpProxy {
    class Constants {
        public const int Port = 9018;
        public const string RequestRegex = @"^[A-Z]+\s+(http://)?([\w\.]*)(:[0-9]{1,5})?(/[\w/]*)?(\?[\w=\&\%\-+\.]*)?\s+HTTP/.*";
        public const string GetParamsRegex = @"^GET\s+/([\w/]*)?(\?[\w=\&\%\-+\.]*)?\s+HTTP/.*";
        public const string ContentTypeHeader = "Content-Type: application/x-www-form-urlencoded";
        public const string HostHeaderRegex = @"(Host:\s([\w.\-_]+)\r\n)";
        public const string ProxyHeaderRegex = @"(Proxy-Connection:\s[\w-]+\r\n)";
        public const string RequestStorage = "RequestStorage.txt";
        public const string RequestStorageSeparator = "\n--------------------------------------\n";
        public static readonly string[] RepeaterArgs = new string[] {"repeater", "--repeater", "r", "-r"};
        public const string RepeaterExitCommand = "exit";
        public const string RepeaterPrintCommand = "print";
        public const string RepeaterAllCommand = "all";
        public const string RepeaterXSSCommand = "xss";
        public const string XSSProbe = "vulnerable'\"><img src onerror=alert()>";
    }

    class Server {
        private TcpListener Listener;

        public Server(int Port) {
            this.Listener = new TcpListener(IPAddress.Any, Port);
            this.Listener.Start();
            Console.WriteLine("Started server on port " + Port + "\n");
            while (true) {
                this.HandleRequest(this.Listener.AcceptTcpClient());
            }
        }

        ~Server() {
            this.Listener.Stop();
        }

        public static void Main(string[] args) {
            Console.CancelKeyPress += new ConsoleCancelEventHandler(Exit);
            if (args.Length > 0 && Array.Exists(Constants.RepeaterArgs, arg => arg == args[0])) {
                new Repeater();
            } else {
                new Server(Constants.Port);
            }
        }

        private static void Exit(object sender, ConsoleCancelEventArgs args) {
            Environment.Exit(1);
        }

        private void HandleRequest(TcpClient Client) {
            Console.WriteLine("new client");
            string Request = "";
            byte[] Buffer = new byte[1024];
            do {
                int Count = Client.GetStream().Read(Buffer, 0, Buffer.Length);
                Request += Encoding.UTF8.GetString(Buffer, 0, Count);
            } while (Client.GetStream().DataAvailable);
            // Console.WriteLine("Original request:\n" + Request);
            Match RequestMatch = Regex.Match(Request, Constants.RequestRegex);
            string RequestHost = RequestMatch.Groups[2].Value;
            // Console.WriteLine("Request host: " + RequestHost);
            if (RequestMatch.Groups[1].Value != "") {
                Request = Request.Replace(RequestMatch.Groups[1].Value, "");
            }
            Request = Request.Substring(0, Request.IndexOf(RequestHost)) +
                (RequestMatch.Groups[4].Value == "" ? "/" : "") +
                Request.Substring(Request.IndexOf(RequestHost) + RequestHost.Length);
            if (RequestMatch.Groups[3].Value != "") {
                Request = Request.Substring(0, Request.IndexOf(RequestMatch.Groups[3].Value)) +
                    Request.Substring(
                        Request.IndexOf(RequestMatch.Groups[3].Value) +
                        RequestMatch.Groups[3].Value.Length
                    );
            }
            RequestMatch = Regex.Match(Request, Constants.ProxyHeaderRegex);
            if (RequestMatch != Match.Empty) {
                // Console.WriteLine("Contains Proxy-Connection");
                // Console.WriteLine(RequestMatch.Groups[1].Value);
                Request = Request.Replace(RequestMatch.Groups[1].Value, "");
            }
            // Console.WriteLine("Request:\n" + Request);
            Console.WriteLine("sending request...");
            TcpClient ProxyClient = new TcpClient();
            ProxyClient.Connect(RequestHost, 80);
            byte[] RequestBuffer = System.Text.Encoding.UTF8.GetBytes(Request);
            ProxyClient.GetStream().Write(RequestBuffer, 0, RequestBuffer.Length);
            Console.WriteLine("waiting for response...");
            do {
                int Count = ProxyClient.GetStream().Read(Buffer, 0, Buffer.Length);
                Client.GetStream().Write(Buffer, 0, Count);
            } while (ProxyClient.GetStream().DataAvailable);
            Console.WriteLine("response got and redirected");
            Console.WriteLine("storing request...");
            this.StoreRequest(Request);
            ProxyClient.GetStream().Close();
            ProxyClient.Close();
            Client.GetStream().Close();
            Client.Close();
            Console.WriteLine("connection closed\n");
        }

        private void StoreRequest(string Request) {
            if (!File.Exists(Constants.RequestStorage)) {
                File.Create(Constants.RequestStorage).Dispose();
            }
            string[] StoredRequests = File.ReadAllText(Constants.RequestStorage).Split(Constants.RequestStorageSeparator);
            if (StoredRequests.Length > 0 && StoredRequests[StoredRequests.Length - 1] == Request) {
                return;
            }
            File.AppendAllText(Constants.RequestStorage, (StoredRequests[0] == "" ? "" : Constants.RequestStorageSeparator) + Request);
        }
    }

    class Repeater {
        public Repeater() {
            while (true) {
                Console.Write("> ");
                string Input = Console.ReadLine();
                if (Input == Constants.RepeaterExitCommand) {
                    break;
                } else if (Input == Constants.RepeaterPrintCommand) {
                    this.PrintLastRequest();
                } else if (Input == Constants.RepeaterXSSCommand) {
                    this.XSSRepeat();
                } else if (Input == Constants.RepeaterAllCommand) {
                    this.Repeat(-1);
                    Console.WriteLine("repeated");
                } else {
                    int Amount;
                    try {
                        Amount = Int32.Parse(Input);
                    } catch {
                        continue;
                    }
                    this.Repeat(Amount);
                    Console.WriteLine("repeated");
                }
            }
        }

        private void PrintLastRequest() {
            if (!File.Exists(Constants.RequestStorage)) {
                Console.WriteLine("No request found in storage. Aborting...");
                return;
            }
            string[] StoredRequests = File.ReadAllText(Constants.RequestStorage).Split(Constants.RequestStorageSeparator);
            Console.WriteLine(StoredRequests[StoredRequests.Length - 1]);
        }

        private bool ReadStorage(string[] StoredRequests) {
            if (!File.Exists(Constants.RequestStorage)) {
                return false;
            }
            StoredRequests = File.ReadAllText(Constants.RequestStorage).Split(Constants.RequestStorageSeparator);
            return StoredRequests.Length > 0;
        }

        private void Repeat(int Amount) {
            string[] StoredRequests;
            if (!this.ReadStorage(StoredRequests)) {
                Console.WriteLine("No request found in storage. Aborting...");
                return;
            }
            int LastRepeatedIndex = (Amount == -1 ? 0 : StoredRequests.Length - Amount);
            LastRepeatedIndex = (LastRepeatedIndex < 0 ? 0 : LastRepeatedIndex);
            for (int i = StoredRequests.Length - 1; i >= LastRepeatedIndex; i--) {
                // Console.WriteLine("Request:\n" + StoredRequests[i] + "\n");
                Match RequestMatch = Regex.Match(StoredRequests[i], Constants.HostHeaderRegex);
                this.MakeRequest(RequestMatch.Groups[2].Value, StoredRequests[i], false);
            }
        }

        private void XSSRepeat() {
            string[] StoredRequests;
            if (!this.ReadStorage(StoredRequests)) {
                Console.WriteLine("No request found in storage. Aborting...");
                return;
            }
            string Request = StoredRequests[StoredRequests.Length - 1];
            Match RequestMatch = Regex.Match(Request, Constants.GetParamsRegex);
            string Group = RequestMatch.Groups[2].Value;
            if (Group == "" || !Group.Contains("=")) {
                Group = Request.Split("\r\n\r\n")[1];
                if (!Request.StartsWith("POST") || !Request.Contains(Constants.ContentTypeHeader) || Group == "" || !Group.Contains("=")) {
                    Console.WriteLine("Eather last request is not GET/POST request, or there are no GET/POST parameters in it. Aborting...");
                    return;
                }
            }
            // Console.WriteLine("Query: " + Group);
            string[] Params = Group.Split("&");
            if (Params[0][0] == '?') {
                Params[0] = Params[0].Substring(1);
            }
            if (Params[Params.Length - 1].EndsWith("\r\n")) {
                Params[Params.Length - 1] = Params[Params.Length - 1].Substring(0, Params[Params.Length - 1].Length - 2);
            }
            RequestMatch = Regex.Match(Request, Constants.HostHeaderRegex);
            bool Vulnerable = false;
            // Console.WriteLine("Parameters: ");
            foreach (string Param in Params) {
                // Console.WriteLine("  " + Param + "$");
                Request = Request.Replace(Param, Param + Constants.XSSProbe);
                string Response = this.MakeRequest(RequestMatch.Groups[2].Value, Request, true);
                if (Response.Split("\r\n\r\n").Length > 1 && Response.Split("\r\n\r\n")[1].Contains(Constants.XSSProbe)) {
                    Console.WriteLine("GET/POST parameter \"" + Param.Substring(0, Param.IndexOf("=")) + "\" is vulnerable");
                    Vulnerable = true;
                }
            }
            if (!Vulnerable) {
                Console.WriteLine("No vulnerabilities found");
            }
        }

        private string MakeRequest(string Host, string Request, bool ReturnResponse) {
            TcpClient Client = new TcpClient();
            Client.Connect(Host, 80);
            byte[] RequestBuffer = Encoding.UTF8.GetBytes(Request);
            Client.GetStream().Write(RequestBuffer, 0, RequestBuffer.Length);
            string Response = "";
            if (ReturnResponse) {
                byte[] Buffer = new byte[1024];
                do {
                    int Count = Client.GetStream().Read(Buffer, 0, Buffer.Length);
                    Response += Encoding.UTF8.GetString(Buffer, 0, Count);
                } while (Client.GetStream().DataAvailable);
            }
            Client.GetStream().Close();
            Client.Close();
            return Response;
        }
    }
}
