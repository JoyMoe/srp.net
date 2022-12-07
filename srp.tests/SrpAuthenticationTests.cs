using System;
using System.Linq;
using System.Security.Cryptography;
using NUnit.Framework;

#if !NET_35
using System.Threading.Tasks;
#endif

namespace SecureRemotePassword.Tests
{
    /// <summary>
    /// Test class for SRP-6a protocol implementation.
    /// </summary>
    [TestFixture]
    public class SrpAuthenticationTests
    {
        [Test]
        public void SrpShouldAuthenticateAUser() {
            // default parameters: RFC5054, 2048-bit group
            SrpAuthentication("linus@folkdatorn.se", "$uper$ecure");

            // sha512, 512-bit prime number
            var parameters = SrpParameters.Create<SHA512>(
                "D4C7F8A2B32C11B8FBA9581EC4BA4F1B04215642EF7355E37C0FC0443EF756EA2C6B8EEB755A1C723027663CAA265EF785B8FF6A9B35227A52D86633DBDFCA43",
                "03");
            SrpAuthentication("yallie@yandex.ru", "h4ck3r$", parameters);

            // md5, 1024-bit prime number from wikipedia (generated using "openssl dhparam -text 1024")
            parameters = SrpParameters.Create<SHA384>(
                "00c037c37588b4329887e61c2da3324b1ba4b81a63f9748fed2d8a410c2fc21b1232f0d3bfa024276cfd88448197aae486a63bfca7b8bf7754dfb327c7201f6fd17fd7fd74158bd31ce772c9f5f8ab584548a99a759b5a2c0532162b7b6218e8f142bce2c30d7784689a483e095e701618437913a8c39c3dd0d4ca3c500b885fe3",
                "07");
            SrpAuthentication("bozo", "h4ck3r", parameters);

            // sha1 hash function, default N and g values for all standard groups
            SrpAuthenticationUsingStandardParameters<SHA1>("hello", "world");
        }

        // [Test, Explicit]
        public void SrpStressTest() {
            // 100 iterations take ~10 minutes on my machine
            for (var i = 0; i < 100; i++) {
                SrpShouldAuthenticateAUser();
            }
        }

        // [Test, Explicit]
        public void SrpUsingStandardParameters() {
            // takes ~42 seconds on my machine
            SrpAuthenticationUsingStandardParameters<SHA1>("user", "password");
            SrpAuthenticationUsingStandardParameters<SHA256>("LongUser", "stronger-password");
            SrpAuthenticationUsingStandardParameters<SHA384>("root", "$hacker$");
            SrpAuthenticationUsingStandardParameters<SHA512>("Administrator", "123456");
            SrpAuthenticationUsingStandardParameters<MD5>("not-safe", "dont-use");
        }

        private void SrpAuthenticationUsingStandardParameters<T>(string username, string password)
            where T : HashAlgorithm {
            // test all standard groups using the same hashing algorithm
            SrpAuthentication(username, password, SrpParameters.Create1024<T>());
            SrpAuthentication(username, password, SrpParameters.Create1536<T>());
            SrpAuthentication(username, password, SrpParameters.Create2048<T>());
            SrpAuthentication(username, password, SrpParameters.Create3072<T>());
            SrpAuthentication(username, password, SrpParameters.Create4096<T>());
            SrpAuthentication(username, password, SrpParameters.Create6144<T>());
            SrpAuthentication(username, password, SrpParameters.Create8192<T>());
        }

        private void SrpAuthentication(string username, string password, SrpParameters parameters = null) {
            // use default parameters if not specified: sha256, 2048-bit prime number
            var client = new SrpClient(parameters);
            var server = new SrpServer(parameters);

            // sign up
            var salt       = client.GenerateSalt();
            var privateKey = client.DerivePrivateKey(salt, username, password);
            var verifier   = client.DeriveVerifier(privateKey);

            // authenticate
            var clientEphemeral = client.GenerateEphemeral();
            var serverEphemeral = server.GenerateEphemeral(verifier);
            var clientSession = client.DeriveSession(clientEphemeral.Secret, serverEphemeral.Public, salt, username,
                privateKey);

            try {
                var serverSession = server.DeriveSession(serverEphemeral.Secret, clientEphemeral.Public, salt, username,
                    verifier, clientSession.Proof);
                client.VerifySession(clientEphemeral.Public, clientSession, serverSession.Proof);

                // make sure both the client and the server have the same session key
                Assert.AreEqual(clientSession.Key, serverSession.Key);
            } catch {
                // generate the regression test code
                Console.WriteLine("// regression test:");
                Console.WriteLine($"var parameters = {parameters?.ToString() ?? "new SrpParameters()"};");
                Console.WriteLine($"var serverEphemeral = new SrpEphemeral");
                Console.WriteLine($"{{");
                Console.WriteLine($"	Secret = \"{serverEphemeral.Secret}\",");
                Console.WriteLine($"	Public = \"{serverEphemeral.Public}\",");
                Console.WriteLine($"}};");
                Console.WriteLine();
                Console.WriteLine($"var clientEphemeral = new SrpEphemeral");
                Console.WriteLine($"{{");
                Console.WriteLine($"	Secret = \"{clientEphemeral.Secret}\",");
                Console.WriteLine($"	Public = \"{clientEphemeral.Public}\",");
                Console.WriteLine($"}};");
                Console.WriteLine();
                Console.WriteLine($"var salt = \"{salt}\";");
                Console.WriteLine($"var username = \"{username}\";");
                Console.WriteLine($"var privateKey = \"{privateKey}\";");
                Console.WriteLine($"var verifier = \"{verifier}\";");
                Console.WriteLine($"var clientSessionProof = \"{clientSession.Proof}\";");
                Console.WriteLine($"var serverSessionKey = \"{clientSession.Key}\";");
                Console.WriteLine($"var serverSessionProof = \"????\";");
                Console.WriteLine();
                Console.WriteLine(
                    $"var clientSession = new SrpClient(parameters).DeriveSession(clientEphemeral.Secret, serverEphemeral.Public, salt, username, privateKey);");
                Console.WriteLine($"Assert.IsNotNull(clientSession);");
                Console.WriteLine($"Assert.AreEqual(serverSessionKey, clientSession.Key);");
                Console.WriteLine($"Assert.AreEqual(clientSessionProof, clientSession.Proof);");
                Console.WriteLine();
                Console.WriteLine(
                    $"var serverSession = new SrpServer(parameters).DeriveSession(serverEphemeral.Secret, clientEphemeral.Public, salt, username, verifier, clientSessionProof);");
                Console.WriteLine($"Assert.IsNotNull(serverSession);");
                Console.WriteLine($"Assert.AreEqual(serverSessionKey, serverSession.Key);");
                Console.WriteLine($"Assert.AreEqual(serverSessionProof, serverSession.Proof);");
                throw;
            }
        }

#if !NET_35
        [Test]
        public async Task ParallelAuthenticationTest() {
            var username   = "demo";
            var password   = "insecure";
            var parameters = new SrpParameters();
            var server     = new SrpServer(parameters);

            // spawn multiple parallel threads reusing the same SrpParameters instance
            var tasks = Enumerable.Range(0, 100).Select(i => Task.Run(() => {
                var client = new SrpClient(parameters);

                // sign up
                var salt       = client.GenerateSalt();
                var privateKey = client.DerivePrivateKey(salt, username, password);
                var verifier   = client.DeriveVerifier(privateKey);

                // authenticate
                var clientEphemeral = client.GenerateEphemeral();
                var serverEphemeral = server.GenerateEphemeral(verifier);
                var clientSession = client.DeriveSession(clientEphemeral.Secret, serverEphemeral.Public, salt, username,
                    privateKey);

                var serverSession = server.DeriveSession(serverEphemeral.Secret, clientEphemeral.Public, salt, username,
                    verifier, clientSession.Proof);
                client.VerifySession(clientEphemeral.Public, clientSession, serverSession.Proof);

                // make sure both the client and the server have the same session key
                Assert.AreEqual(clientSession.Key, serverSession.Key);

                // verify padded length of all parameters
                Assert.AreEqual(verifier.Length, parameters.PaddedLength);
                Assert.AreEqual(clientEphemeral.Public.Length, parameters.PaddedLength);
                Assert.AreEqual(clientEphemeral.Secret.Length, parameters.HashSizeBytes * 2);
                Assert.AreEqual(serverEphemeral.Public.Length, parameters.PaddedLength);
                Assert.AreEqual(serverEphemeral.Secret.Length, parameters.HashSizeBytes * 2);
                Assert.AreEqual(serverSession.Key.Length, parameters.HashSizeBytes * 2);
                Assert.AreEqual(clientSession.Key.Length, parameters.HashSizeBytes * 2);
                Assert.AreEqual(serverSession.Proof.Length, parameters.HashSizeBytes * 2);
                Assert.AreEqual(clientSession.Proof.Length, parameters.HashSizeBytes * 2);
            }));

            await Task.WhenAll(tasks);
        }
#endif
    }
}
