/*  Comms. It's for communication. Privately.
    Copyright (C) 2026 A2

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.*/
//pragma
#pragma warning disable CS0219
#pragma warning disable CS8321
#pragma warning disable CS1633
#pragma warning disable CS1634
#pragma warning disable CS8602
#pragma warning disable CS8981
#pragma warning disable CS8604
//using
using System.Security.Cryptography.X509Certificates;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Net.Security;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading;
using System.Text;
using System.Net;
//error
int errorBytesReadTooLarge = 0;
//var
const string accdbFile = "accounts.jsonl";
const string ipaDB = "ipauuid.txt"; 
var accdbFileCont = File.ReadAllText(accdbFile);
if (ipaDBExists(ipaDB) == true) {
    }
else if (ipaDBExists(ipaDB) == false) {
        File.AppendAllText(ipaDB, "");
    }
//func
static bool errorBytesReadTooLargeBool(int bytesRead) {
    if (bytesRead > 1048575) {
        return true;
    }
    else {
        return false;
    }
}
static bool ipaDBExists(string ipaDB) {
    if (File.Exists(ipaDB)) {
        return true;
    }
    return false;
}
static bool ipex(TcpClient client, string ipaDBCont, string[] ipaDBLines) {
    var ipa = (IPEndPoint)client.Client.RemoteEndPoint;
    foreach (string ipaDBLine in ipaDBLines){
        if (ipaDBLine == ipa.Address.ToString()) {
            return true;
        }
    }
    return false;
}
static string[] ipaDBLinesCheck(string ipaDB, string[] ipaDBLines) {
    Thread.Sleep(250);
    return File.ReadAllLines(ipaDB);
}
static bool accdbFileExists(string accdbFile) {
    if (File.Exists(accdbFile)) {
        return true;
    }
    return false;
}
static string readPassword(System.Text.StringBuilder sb) {
    while (true) {
        var key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.Enter) {
            Console.WriteLine();
            return sb.ToString();
        }
        if (key.Key == ConsoleKey.Backspace && sb.Length > 0) {
            sb.Length--;
            Console.Write("\b \b");
            continue;
        }
        if (char.IsControl(key.KeyChar)) {
            Console.WriteLine("password can't have control combinations in it, try again.");
            sb.Clear();
            Console.Write("Password: ");
            continue;
        }
        if (key.KeyChar == '+') {
            Console.WriteLine("\npassword can't have \"+\" in it, try again.\n");
            sb.Clear();
            Console.Write("Password: ");
            continue;
        }
        if (key.KeyChar != '\0') {
            sb.Append(key.KeyChar);
            Console.Write('*');
        }
    }
}
static string accdbFileContCheck() {
    Thread.Sleep(250);
    return File.ReadAllText(accdbFile);
}
//ifthen0
string ipaDBCont = File.ReadAllText(ipaDB);
string[] ipaDBLines = File.ReadAllLines(ipaDB);
//stuff
TcpListener tcpl = new TcpListener(IPAddress.Any, 9143);
tcpl.Start();
Console.WriteLine("Ready.");
if (args.Length == 2 && args[0] == "clearAcc") {
    File.Delete(accdbFile);
}
if (args.Length == 2 && args[0] == "account" && args[1] == "create") {
        var salt = RandomNumberGenerator.GetBytes(32);
        var sb = new StringBuilder();
        Console.Write("Username: ");
        string usrnm = Console.ReadLine();
        if (accdbFileCont.Contains("{\"Username\":\""+usrnm+"\",\"Salt\"")) {
                Console.WriteLine($"username \"{usrnm}\" already exists. try again.");
                Environment.Exit(0);
            }
        if (usrnm.Contains("\\")) {
            Console.WriteLine($"username can't have backslashes (\\) in it. {usrnm}");
            Environment.Exit(0);
        }
Console.Write("Password: ");
string pw = readPassword(sb);
byte[] hash = Rfc2898DeriveBytes.Pbkdf2(pw,salt,600_000,HashAlgorithmName.SHA512,32);
var rec = new accdb(usrnm, salt, hash, 600_000, "PBKDF2-SHA512");
if (accdbFileExists(accdbFile) == false) {
       Console.WriteLine($"{accdbFile} doesn't exist. creating...");
    }
else if (accdbFileExists(accdbFile) == true) {
       Console.WriteLine($"{accdbFile} exists.");
    }
string ln=JsonSerializer.Serialize(rec);
File.AppendAllText(accdbFile,"");
string[] lnRead = File.ReadAllLines(accdbFile);
accdb? deserializedAccdb = JsonSerializer.Deserialize<accdb>(ln);
Console.WriteLine("username doesn't exist in database.");
File.AppendAllText(accdbFile,ln+"\n");
Console.WriteLine($"deserialised account database: {deserializedAccdb},");
Console.Write($"read lines from accounts.jsonl: \n");
Console.WriteLine(string.Join("\n", File.ReadAllLines(accdbFile)));
string saltb64 = Convert.ToBase64String(salt);
string hashb64 = Convert.ToBase64String(hash);
    }

//tcplistener
if (args.Length == 1 && args[0] == "tcpListener") {
    for (;;) {
TcpClient client = tcpl.AcceptTcpClient();
NetworkStream stream = client.GetStream();
byte[] maxContentSize = new byte[1048576];
int bytesRead = stream.Read(maxContentSize, 0, maxContentSize.Length);
string cont  = Encoding.UTF8.GetString(maxContentSize, 0, bytesRead);
errorBytesReadTooLargeBool(bytesRead);
Console.ForegroundColor = ConsoleColor.Green;
Console.WriteLine("Connection accepted");
Console.ResetColor();
Console.WriteLine($"Contents: {cont}. Bytes recieved: {bytesRead}.");
//ifthenloop
if (ipex(client, ipaDBCont, ipaDBLines) == true && args.Length == 0) {
    Console.WriteLine(ipex(client, ipaDBCont, ipaDBLines));
}
else if (ipex(client, ipaDBCont, ipaDBLines) == false && args.Length == 0) {
        Console.WriteLine(ipex(client, ipaDBCont, ipaDBLines));

}
if (errorBytesReadTooLargeBool(bytesRead) == true) {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"Error {errorBytesReadTooLarge}: Bytes read {bytesRead}.");
        Console.ResetColor();
        client.Close();
        }
if (args.Length == 0) {
    var ipa = (IPEndPoint)client.Client.RemoteEndPoint;
    Console.WriteLine($"{ipa.Address}:{ipa.Port}");
        if (ipex(client, ipaDBCont, ipaDBLines) == false) {
                File.AppendAllText(ipaDB, $"{ipa.Address.ToString()}\n");
        }
    }
}
}
public sealed record accdb(string Username,byte[] Salt,byte[] Hash,int Iterations,string Algorithm);
