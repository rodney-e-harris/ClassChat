/*
Rodney Harris
*/

using System.IO;
using static System.Environment;
using static System.IO.Path;
using System.Security.Cryptography;
using System.Text;
using System.Net.Sockets;
using System.Net;

Console.WriteLine("Class Chat Client Two:");
Client();

/*
 * Client
 *
 * Output: Strings to the server that client types to make requests to the server
*/
static void Client()
{
    
    using var connectionToServer = new TcpClient("localhost", 8081);
    using var theServer = connectionToServer.GetStream();

    var br = new BinaryReader(theServer);
    var bw = new BinaryWriter(theServer);
    
    new StreamFromServerInput(br);

    Console.WriteLine("1-Register a new user account");
    Console.WriteLine("2-Send a message to a user account");
    Console.WriteLine("3-Get all messages for a user account");
    Console.WriteLine("0-Exit");

    var input = Console.ReadLine();
    var newCommand = true;
    var readingMenu = false;
    var name = " ";

    try
    {
        while (true)
        {
            if(readingMenu)
            {
                Console.WriteLine("1-Register a new user account");
                Console.WriteLine("2-Send a message to a user account");
                Console.WriteLine("3-Get all messages for a user account");
                Console.WriteLine("0-Exit");

                input = Console.ReadLine();
                if(input == "1" || input == "2" || input == "3" || input == "0")
                {
                    readingMenu = false;
                    newCommand = true;
                }
                
                Console.WriteLine("");
            }
            if(input == "1" && newCommand) {
                newCommand = false;

                Console.WriteLine("Enter your username:");

                name = Console.ReadLine();

                using (var rsa = new RSACryptoServiceProvider())
                {
                    File.WriteAllText(Combine(CurrentDirectory, name + "PublicKeyOnly.xml"), rsa.ToXmlString (false));
                    File.WriteAllText(Combine(CurrentDirectory, name + "PrivateKeyOnly.xml"), rsa.ToXmlString(true));
                }

                var message = name + "~" + File.ReadAllText(Combine(CurrentDirectory, name +"PublicKeyOnly.xml"));
                bw.Write(message);
                bw.Flush();

                readingMenu = true;
                
                Console.WriteLine("");

            }
            else if(input == "2" && newCommand) {
                newCommand = false;
                
                Console.WriteLine("Enter a your username: ");
                var sender = Console.ReadLine();
                Console.WriteLine("Enter a user to receive messages: ");
                var receiver = Console.ReadLine();
                Console.WriteLine("Enter a message: ");
                var message = Console.ReadLine();

                bw.Write("*Receiver:" + receiver + "*,*" + "<" + sender + ">: " + message);
                bw.Flush();

                readingMenu = true;
                
                Console.WriteLine("");
            }
            else if(input == "3" && newCommand) {
                newCommand = false;


                Console.WriteLine("Enter a user to get messages: ");
                var getter = Console.ReadLine();

                bw.Write("*Getter:" + getter);

                bw.Flush();

                readingMenu = true;
                
                Console.WriteLine("");
            }
            else if(input == "0" && newCommand){
                newCommand = false;

                connectionToServer.Close();
                
            }

        }
    }
    catch
    {
        bw.Close();
    }
}

/*
 * StramFromServerInput
 *
 * Class for receiving input from the server for client interactions
*/
internal class StreamFromServerInput
{
    /*
     * StreamFromServerInput
     *
     * Runs a thread for InputLoop to constantly listen for client input
     *
     * Input: br (BinaryReader for receiving client input)
    */
    public StreamFromServerInput(BinaryReader br)
    {
        Task.Run(() => InputLoop(br)); 
    }

    static string lastMD = "";

    /*
     * PassByteString
     *
     * Decrypts the encrypted message sent from the server for user retrieval
     *
     * Input: getter (name of the receiver), byteString (encrypted message from server)
     * Output: decrypted message
    */
    static void PassByteString(string getter, string byteString) {

        string publicPrivate = File.ReadAllText(Combine(CurrentDirectory,getter + "PrivateKeyOnly.xml"));

        byte[] dataout = Convert.FromBase64String(byteString);

        string messageDecrypted;

        byte[] decrypted;
        using (var rsaPublicPrivate = new RSACryptoServiceProvider())
        {
            rsaPublicPrivate.FromXmlString (publicPrivate);
            decrypted = rsaPublicPrivate.Decrypt(dataout, true);
            messageDecrypted = Encoding.UTF8.GetString(decrypted);
        }

        

        if (lastMD != messageDecrypted)
        {
            Console.WriteLine("--------");
            Console.WriteLine("Messages");
            Console.WriteLine("--------");
            Console.WriteLine(messageDecrypted);
            Console.WriteLine("");
            Console.WriteLine("Enter a new command:");
        }
        
        lastMD = messageDecrypted;
    
    }

    /*
     * InputLoop
     *
     * Asynchronous method that listens for client input
     *
     * Input: br (BinaryReader for receiving client input)
     * Output: Passes receiver name and message to PassByteString
     * 
    */
    private async void InputLoop(BinaryReader br) {
        try
        {
            while (true)
            {
                var incoming = br.ReadString();

                if(incoming.Contains("::")) {
                    var incomingSplit = incoming.Split("::");
                    PassByteString(incomingSplit[0], incomingSplit[1]);
                }

            }
        }
        catch
        {
            br.Close();
        }
    }
}
