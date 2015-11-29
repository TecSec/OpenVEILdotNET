//	Copyright (c) 2015, TecSec, Inc.
//
//	Redistribution and use in source and binary forms, with or without
//	modification, are permitted provided that the following conditions are met:
//	
//		* Redistributions of source code must retain the above copyright
//		  notice, this list of conditions and the following disclaimer.
//		* Redistributions in binary form must reproduce the above copyright
//		  notice, this list of conditions and the following disclaimer in the
//		  documentation and/or other materials provided with the distribution.
//		* Neither the name of TecSec nor the names of the contributors may be
//		  used to endorse or promote products derived from this software 
//		  without specific prior written permission.
//		 
//	ALTERNATIVELY, provided that this notice is retained in full, this product
//	may be distributed under the terms of the GNU General Public License (GPL),
//	in which case the provisions of the GPL apply INSTEAD OF those given above.
//		 
//	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
//	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//	DISCLAIMED.  IN NO EVENT SHALL TECSEC BE LIABLE FOR ANY 
//	DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
//	LOSS OF USE, DATA OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
//	ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
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
