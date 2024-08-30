using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

class MessageEncrypter
{
	static async Task Main(string[] args)
	{
		Console.Write("Enter a message to encrypt: ");
        string originalMessage = Console.ReadLine() ?? string.Empty;

		Console.Write("Enter a password: ");
		string password = Console.ReadLine() ?? string.Empty;

		(byte[] encryptedMessage, byte[] salt, byte[] iv) = EncryptMessage(originalMessage, password);
		
		Console.WriteLine("Encrypted Message: " + Convert.ToBase64String(encryptedMessage));
		Console.WriteLine("Salt: " + Convert.ToBase64String(salt));
		Console.WriteLine("IV: " + Convert.ToBase64String(iv));

		string decryptedMessage = DecryptMessage(encryptedMessage, password, salt, iv);
		Console.WriteLine("Decrypted Message: " + decryptedMessage);

		await SendEncryptedMessage(Convert.ToBase64String(encryptedMessage));
	}

	static (byte[], byte[], byte[]) EncryptMessage(string message, string password)
	{
		using (Aes aesAlg = Aes.Create())
		{
			byte[] salt = GenerateSalt();
			aesAlg.Key = DeriveKeyFromPassword(password, salt);
			aesAlg.GenerateIV();

			ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

			using (MemoryStream msEncrypt = new MemoryStream())
			{
				using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
				{
					using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
					{
						swEncrypt.Write(message);
					}
					byte[] encrypted = msEncrypt.ToArray();
					return (encrypted, salt, aesAlg.IV);
				}
			}
		}
	}

	static string DecryptMessage(byte[] encryptedMessage, string password, byte[] salt, byte[] iv)
	{
		using (Aes aesAlg = Aes.Create())
		{
			aesAlg.Key = DeriveKeyFromPassword(password, salt);
			aesAlg.IV = iv;

			ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

			using (MemoryStream msDecrypt = new MemoryStream(encryptedMessage))
			{
				using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
				{
					using (StreamReader srDecrypt = new StreamReader(csDecrypt))
					{
						return srDecrypt.ReadToEnd();
					}
				}
			}
		}
	}

	static byte[] GenerateSalt()
	{
		byte[] salt = new byte[16];
		using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
		{
			rng.GetBytes(salt);
		}
		return salt;
	}

	static byte[] DeriveKeyFromPassword(string password, byte[] salt)
	{
		using (var keyDerivationFunction = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256))
		{
			return keyDerivationFunction.GetBytes(32); // 256-bit key
		}
	}

	static async Task SendEncryptedMessage(string encryptedContent)
	{
		using (var client = new HttpClient())
		{
			var message = new { content = encryptedContent };
			var json = JsonConvert.SerializeObject(message);
			var content = new StringContent(json, Encoding.UTF8, "application/json");

			var response = await client.PostAsync("http://localhost:5090/api/messages", content);

			if (response.IsSuccessStatusCode)
			{
				Console.WriteLine("Encrypted message sent successfully.");
			}
			else
			{
				Console.WriteLine("Failed to send encrypted message.");
			}
		}
	}
}
