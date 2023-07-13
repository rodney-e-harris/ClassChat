/*
Rodney Harris
*/

using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using p2server_C00441253_C00445623;


var clientList = new List<StreamFromClientInput>();
List<Tuple<string, string>> clientListPseudoDB = new List<Tuple<string, string>>();
List<Tuple<string, string>> messagesPseudoDB = new List<Tuple<string, string>>();
XmlDocument keyAccess = new XmlDocument();

var listen = new TcpListener(IPAddress.Any, 8081);
listen.Start();
Console.WriteLine("Listening for client on 8081 ...");

while (true)
{
    var clientConnect = listen.AcceptTcpClient();
    var theClient = clientConnect.GetStream();

    var bw = new BinaryWriter(theClient);
    var br = new BinaryReader(theClient);

    var sfcInput = new StreamFromClientInput(br, bw, clientList, clientListPseudoDB, messagesPseudoDB);
    lock (clientList)
    {
        clientList.Add(sfcInput);
    }
}

/*
 * StreamFromClientInput
 *
 * Class for receiving the String inputs from the client(s) and handling the requests
*/
namespace p2server_C00441253_C00445623
{
    internal class StreamFromClientInput
    {
        private readonly BinaryWriter bw;

        /*
     * StreamFromClientInput
     *
     * Runs a thread to listen for messages from the client 
    */
        public StreamFromClientInput(BinaryReader br, BinaryWriter bw, List<StreamFromClientInput> list, List<Tuple<string,string>> pseudoDB, List<Tuple<string,string>> messageDB)
        {
            this.bw = bw;
            Task.Run(() =>  InputLoop(br, list, pseudoDB, messageDB));
        }

        /*
     * InputLoop
     *
     * Receives messages from the clients that contain requests for the server to handle 
     *
     * Input: br (BinaryReader for receiving client input), list (list of clients), 
     *        pseudoDB (Stores client names and public keys), messageDB (stores messages from clients)
     * 
     * Output: Encrypted messages 
    */
        private async Task InputLoop(BinaryReader br, List<StreamFromClientInput> list, List<Tuple<string,string>> pseudoDB, List<Tuple<string,string>> messageDB)
        {
            try
            {
                while (true)
                {
                    //waits for input from client
                    var incoming = br.ReadString();
                    foreach (var c in list)
                        try
                        {
                            c.bw.Write(incoming);

                            if(incoming.Contains("~") && incoming.Contains("<RSAKeyValue>"))
                            {
                                var newUser = true;
                                var userTuple = incoming.Split("~");

                                foreach (Tuple<string, string> uTuple in pseudoDB)
                                {
                                    if (uTuple.Item1 == userTuple[0])
                                    {
                                        newUser = false;
                                    }
                                }

                                if (newUser)
                                {
                                    pseudoDB.Add(new Tuple<string,string>(userTuple[0], userTuple[1]));
                                }

                                Console.WriteLine(pseudoDB.Last());
                            }
                        
                            // Used when a message is sent from client side to be encrypted and stored for when the receiving
                            // user wants to see their messages.
                        
                            if(incoming.Contains("*Receiver:")) {
                                var newMessage = incoming.Replace("*Receiver:", "");
                                var newMessageArr = newMessage.Split("*,*");

                                foreach(Tuple<string,string> uTuple in pseudoDB)
                                {
                                    if(uTuple.Item1 == newMessageArr[0])
                                    {
                                        byte[] datain = Encoding.UTF8.GetBytes (newMessageArr[1]);
                                        string publicKeyOnly = uTuple.Item2;
                                        byte[] encrypted;
                                        using (var rsaPublicOnly = new RSACryptoServiceProvider())
                                        {
                                            rsaPublicOnly.FromXmlString (publicKeyOnly);
                                            encrypted = rsaPublicOnly.Encrypt (datain, true);
                                        }

                                        var encryptedMessage = Convert.ToBase64String(encrypted);

                                        messageDB.Add(new Tuple<string,string>(uTuple.Item1, uTuple.Item1 + "::" + encryptedMessage)); 
                                    }
                                    else
                                    {

                                    }
                                }        
                            }

                            //Checks when someone attempt to receive messages on the client side

                            if(incoming.Contains("*Getter:")) {
                                var gettingMessage = incoming.Replace("*Getter:", "");

                                foreach(Tuple<string,string> uTuple in messageDB)
                                {
                                    if(uTuple.Item1 == gettingMessage)
                                    {
                                    
                                        bw.Write(uTuple.Item2);
                                        bw.Flush();
                                    
                                    }
                                }

                            }

                        }
                        catch
                        {
                            c.bw.Close();
                        }
                }
            }
            catch
            {
                br.Close();
            }
        }
    }
}



