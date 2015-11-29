using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using OpenVEIL;
using DynamicJsonParser;

namespace tokenList
{
    class Program
    {
        static void Main(string[] args)
        {
            OpenVEIL.Environment env = new OpenVEIL.Environment();
            try
            {
                env.InitializeVEIL(false);

                KeyVEILConnector kvConn = new KeyVEILConnector();
                kvConn.connect("http://localhost:8125", "user1", "11111111");

                for (int i = 0; i < kvConn.tokenCount; i++)
                {
                    Token token = kvConn.tokenByIndex(i);
                    Console.WriteLine();
                    Console.WriteLine("Token");
                    Console.WriteLine("  Name;            " + token.tokenName);
                    Console.WriteLine("  Type:            " + token.tokenType);
                    Console.WriteLine("  serialNumber:    " + BitConverter.ToString(token.serialNumber()).Replace("-",""));
                    Console.WriteLine("  id:              " + token.id.ToString("B"));
                    Console.WriteLine("  Enterprise name: " + token.enterpriseName);
                    Console.WriteLine("  Enterprise ID:   " + token.enterpriseId.ToString("B"));
                    Console.WriteLine("  Member Name:     " + token.memberName);
                    Console.WriteLine("  Member ID:       " + token.memberId.ToString("B"));
                }
                for (int i = 0; i < kvConn.favoriteCount; i++)
                {
                    Favorite fav = kvConn.favoriteByIndex(i);
                    Console.WriteLine();
                    Console.WriteLine("Favorite");
                    Console.WriteLine("  Name:         " + fav.favoriteName);
                    Console.WriteLine("  ID:           " + fav.favoriteId.ToString("B"));
                    Console.WriteLine("  Enterprise:   " + fav.enterpriseId.ToString("B"));
                    Console.WriteLine("  Token Serial: " + BitConverter.ToString(fav.getTokenSerialNumber()).Replace("-",""));
                }

                Session session = kvConn.tokenBySerialNumber("906845AEC554109D").openSession();

                Console.WriteLine("SESSION");
                Console.WriteLine("Is Valid:      " + (session.isValid ? "True" : "False"));
                Console.WriteLine("Is logged in:  " + (session.isLoggedIn ? "True" : "False"));

                if (!session.isLoggedIn)
                {
                    Console.WriteLine("  login returned:  " + session.login("11111111").ToString());
                    Console.WriteLine("  Is logged in:  " + (session.isLoggedIn ? "True" : "False"));
                }
                byte[] inData = { 1, 2, 3, 4 };
                Console.WriteLine("Original data: " + BitConverter.ToString(inData));

                byte[] outData = kvConn.favoriteByName("Staff").encryptData(session, inData, true);

                Console.WriteLine("Encrypted data: " + BitConverter.ToString(outData));

                byte[] newSrc = session.decryptData(outData);

                Console.WriteLine("Decrypted data: " + BitConverter.ToString(newSrc));
                Console.WriteLine("File encrypt returned " + (kvConn.favoriteByName("Staff").encryptFile(session, "tokenList.exe", true, "tokenList.exe.ckm") ? "True" : "False"));
                Console.WriteLine("File decrypt returned " + (session.decryptFile("tokenList.exe.ckm", "tokenList2.exe") ? "True" : "False"));
            }
            finally
            {
                env.TerminateVEIL();
            }

        }
    }
}
