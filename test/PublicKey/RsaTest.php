<?php

namespace LaminasTest\Crypt\PublicKey;

use Laminas\Crypt\PublicKey\Rsa;
use Laminas\Crypt\PublicKey\Rsa\Exception;
use Laminas\Crypt\PublicKey\Rsa\PrivateKey;
use Laminas\Crypt\PublicKey\Rsa\PublicKey;
use Laminas\Crypt\PublicKey\RsaOptions;
use PHPUnit\Framework\TestCase;

use function base64_decode;
use function base64_encode;
use function getenv;
use function realpath;
use function strpos;

use const OPENSSL_ALGO_SHA1;
use const OPENSSL_PKCS1_OAEP_PADDING;
use const OPENSSL_PKCS1_PADDING;

/**
 * @group      Laminas_Crypt
 */
class RsaTest extends TestCase
{
    /** @var string */
    protected $testPemString;

    /** @var string */
    protected $testPemFile;

    /** @var string */
    protected $testPemStringPublic;

    /** @var string */
    protected $testCertificateString;

    /** @var string */
    protected $testCertificateFile;

    /** @var string */
    protected $openSslConf;

    /** @var string */
    protected $userOpenSslConf;

    /** @var Rsa */
    protected $rsa;

    /** @var Rsa */
    protected $rsaBase64Out;

    private PrivateKey $privateKey;

    public function setUp(): void
    {
        $openSslConf = false;
        if (isset($_ENV['OPENSSL_CONF'])) {
            $openSslConf = $_ENV['OPENSSL_CONF'];
        } elseif (isset($_ENV['SSLEAY_CONF'])) {
            $openSslConf = $_ENV['SSLEAY_CONF'];
        } elseif (getenv('TESTS_LAMINAS_CRYPT_OPENSSL_CONF')) {
            $openSslConf = getenv('TESTS_LAMINAS_CRYPT_OPENSSL_CONF');
        }
        $this->openSslConf = $openSslConf;

        try {
            $rsa = new Rsa();
        } catch (Rsa\Exception\RuntimeException $e) {
            if (strpos($e->getMessage(), 'requires openssl extension') !== false) {
                $this->markTestSkipped($e->getMessage());
            } else {
                throw $e;
            }
        }

        $this->testPemString = <<<RSAKEY
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBANDiE2+Xi/WnO+s120NiiJhNyIButVu6zxqlVzz0wy2j4kQVUC4Z
RZD80IY+4wIiX2YxKBZKGnd2TtPkcJ/ljkUCAwEAAQJAL151ZeMKHEU2c1qdRKS9
sTxCcc2pVwoAGVzRccNX16tfmCf8FjxuM3WmLdsPxYoHrwb1LFNxiNk1MXrxjH3R
6QIhAPB7edmcjH4bhMaJBztcbNE1VRCEi/bisAwiPPMq9/2nAiEA3lyc5+f6DEIJ
h1y6BWkdVULDSM+jpi1XiV/DevxuijMCIQCAEPGqHsF+4v7Jj+3HAgh9PU6otj2n
Y79nJtCYmvhoHwIgNDePaS4inApN7omp7WdXyhPZhBmulnGDYvEoGJN66d0CIHra
I2SvDkQ5CmrzkW5qPaE2oO7BSqAhRZxiYpZFb5CI
-----END RSA PRIVATE KEY-----

RSAKEY;

        $this->testPemStringPublic   = <<<RSAKEY
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANDiE2+Xi/WnO+s120NiiJhNyIButVu6
zxqlVzz0wy2j4kQVUC4ZRZD80IY+4wIiX2YxKBZKGnd2TtPkcJ/ljkUCAwEAAQ==
-----END PUBLIC KEY-----

RSAKEY;
        $this->testCertificateString = <<<CERT
-----BEGIN CERTIFICATE-----
MIIC6TCCApOgAwIBAgIBADANBgkqhkiG9w0BAQQFADCBhzELMAkGA1UEBhMCSUUx
DzANBgNVBAgTBkR1YmxpbjEPMA0GA1UEBxMGRHVibGluMQ4wDAYDVQQKEwVHcm91
cDERMA8GA1UECxMIU3ViZ3JvdXAxEzARBgNVBAMTCkpvZSBCbG9nZ3MxHjAcBgkq
hkiG9w0BCQEWD2pvZUBleGFtcGxlLmNvbTAeFw0wODA2MTMwOTQ4NDlaFw0xMTA2
MTMwOTQ4NDlaMIGHMQswCQYDVQQGEwJJRTEPMA0GA1UECBMGRHVibGluMQ8wDQYD
VQQHEwZEdWJsaW4xDjAMBgNVBAoTBUdyb3VwMREwDwYDVQQLEwhTdWJncm91cDET
MBEGA1UEAxMKSm9lIEJsb2dnczEeMBwGCSqGSIb3DQEJARYPam9lQGV4YW1wbGUu
Y29tMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANDiE2+Xi/WnO+s120NiiJhNyIBu
tVu6zxqlVzz0wy2j4kQVUC4ZRZD80IY+4wIiX2YxKBZKGnd2TtPkcJ/ljkUCAwEA
AaOB5zCB5DAdBgNVHQ4EFgQUxpguR0f4g+502IxAp3aMZvJ6asMwgbQGA1UdIwSB
rDCBqYAUxpguR0f4g+502IxAp3aMZvJ6asOhgY2kgYowgYcxCzAJBgNVBAYTAklF
MQ8wDQYDVQQIEwZEdWJsaW4xDzANBgNVBAcTBkR1YmxpbjEOMAwGA1UEChMFR3Jv
dXAxETAPBgNVBAsTCFN1Ymdyb3VwMRMwEQYDVQQDEwpKb2UgQmxvZ2dzMR4wHAYJ
KoZIhvcNAQkBFg9qb2VAZXhhbXBsZS5jb22CAQAwDAYDVR0TBAUwAwEB/zANBgkq
hkiG9w0BAQQFAANBAE4M7ZXJTDLHEFguGaP5g64lbmLmLtYX22ZaNY891FmxhtKm
l9Nwj3KnPKFdqzJchujP2TLNwSYoQnxgyoMxdho=
-----END CERTIFICATE-----

CERT;

        $this->testPemFile = realpath(__DIR__ . '/../_files/test.pem');

        $this->testCertificateFile = realpath(__DIR__ . '/../_files/test.cert');

        $this->userOpenSslConf = realpath(__DIR__ . '/../_files/openssl.cnf');

        $this->privateKey = new Rsa\PrivateKey($this->testPemString);

        $rsaOptions = new RsaOptions([
            'private_key' => $this->privateKey,
        ]);
        $this->rsa  = new Rsa($rsaOptions);

        $rsaOptions         = new RsaOptions([
            'private_key'   => $this->privateKey,
            'binary_output' => false,
        ]);
        $this->rsaBase64Out = new Rsa($rsaOptions);
    }

    public function testFactoryCreatesInstance()
    {
        $rsa = Rsa::factory([
            'hash_algorithm'  => 'sha1',
            'binary_output'   => false,
            'private_key'     => $this->testPemString,
            'openssl_padding' => OPENSSL_PKCS1_OAEP_PADDING,
        ]);
        $this->assertInstanceOf(Rsa::class, $rsa);
        $this->assertInstanceOf(RsaOptions::class, $rsa->getOptions());
    }

    public function testFactoryCreatesKeys()
    {
        $rsa = Rsa::factory([
            'private_key' => $this->testPemString,
            'public_key'  => $this->testCertificateString,
        ]);
        $this->assertInstanceOf(PrivateKey::class, $rsa->getOptions()->getPrivateKey());
        $this->assertInstanceOf(PublicKey::class, $rsa->getOptions()->getPublicKey());
    }

    public function testFactoryCreatesKeysFromFiles()
    {
        $rsa = Rsa::factory([
            'private_key' => $this->testPemFile,
        ]);
        $this->assertInstanceOf(PrivateKey::class, $rsa->getOptions()->getPrivateKey());
        $this->assertInstanceOf(PublicKey::class, $rsa->getOptions()->getPublicKey());
    }

    public function testFactoryCreatesJustPublicKey()
    {
        $rsa = Rsa::factory([
            'public_key' => $this->testCertificateString,
        ]);
        $this->assertInstanceOf(PublicKey::class, $rsa->getOptions()->getPublicKey());
        $this->assertNull($rsa->getOptions()->getPrivateKey());
    }

    public function testConstructorCreatesInstanceWithDefaultOptions()
    {
        $rsa = new Rsa();
        $this->assertInstanceOf(Rsa::class, $rsa);
        $this->assertEquals('sha1', $rsa->getOptions()->getHashAlgorithm());
        $this->assertEquals(OPENSSL_ALGO_SHA1, $rsa->getOptions()->getOpensslSignatureAlgorithm());
        $this->assertTrue($rsa->getOptions()->getBinaryOutput());
    }

    public function testPrivateKeyInstanceCreation()
    {
        $privateKey = Rsa\PrivateKey::fromFile($this->testPemFile);
        $this->assertInstanceOf(PrivateKey::class, $privateKey);

        $privateKey = new Rsa\PrivateKey($this->testPemString);
        $this->assertInstanceOf(PrivateKey::class, $privateKey);
    }

    public function testPublicKeyInstanceCreation()
    {
        $publicKey = new Rsa\PublicKey($this->testPemStringPublic);
        $this->assertInstanceOf(PublicKey::class, $publicKey);

        $publicKey = Rsa\PublicKey::fromFile($this->testCertificateFile);
        $this->assertInstanceOf(PublicKey::class, $publicKey);

        $publicKey = new Rsa\PublicKey($this->testCertificateString);
        $this->assertInstanceOf(PublicKey::class, $publicKey);
    }

    public function testSignGeneratesExpectedBinarySignature()
    {
        $signature = $this->rsa->sign('1234567890');
        $this->assertEquals(
            'sMHpp3u6DNecIm5RIkDD3xyKaH6qqP8roUWDs215iOGHehfK1ypqwoETKNP7NaksGS2C1Up813ixlGXkipPVbQ==',
            base64_encode($signature)
        );
    }

    public function testSignGeneratesExpectedBinarySignatureUsingExternalKey()
    {
        $rsaOptions = new RsaOptions([
            'public_key'    => new Rsa\PublicKey($this->testCertificateString),
            'binary_output' => true, // output as binary
        ]);

        $rsa        = new Rsa($rsaOptions);
        $privateKey = new Rsa\PrivateKey($this->testPemString);
        $signature  = $rsa->sign('1234567890', $privateKey);
        $this->assertEquals(
            'sMHpp3u6DNecIm5RIkDD3xyKaH6qqP8roUWDs215iOGHehfK1ypqwoETKNP7NaksGS2C1Up813ixlGXkipPVbQ==',
            base64_encode($signature)
        );
    }

    public function testSignGeneratesExpectedBase64Signature()
    {
        $signature = $this->rsaBase64Out->sign('1234567890');
        $this->assertEquals(
            'sMHpp3u6DNecIm5RIkDD3xyKaH6qqP8roUWDs215iOGHehfK1ypqwoETKNP7NaksGS2C1Up813ixlGXkipPVbQ==',
            $signature
        );
    }

    public function testVerifyVerifiesBinarySignatures()
    {
        $signature = $this->rsa->sign('1234567890');
        $result    = $this->rsa->verify('1234567890', $signature);

        $this->assertTrue($result);
    }

    public function testVerifyVerifiesBinarySignaturesUsingCertificate()
    {
        $rsaOptions = new RsaOptions([
            'public_key'    => new Rsa\PublicKey($this->testCertificateString),
            'binary_output' => true,
        ]);

        $rsa        = new Rsa($rsaOptions);
        $privateKey = new Rsa\PrivateKey($this->testPemString);
        $signature  = $rsa->sign('1234567890', $privateKey);
        $result     = $rsa->verify('1234567890', $signature);

        $this->assertTrue($result);
    }

    public function testVerifyVerifiesBase64Signatures()
    {
        $signature = $this->rsaBase64Out->sign('1234567890');
        $result    = $this->rsaBase64Out->verify('1234567890', $signature);

        $this->assertTrue($result);
    }

    public function testEncryptionWithPublicKey()
    {
        $publicKey  = new Rsa\PublicKey($this->testCertificateString);
        $privateKey = new Rsa\PrivateKey($this->testPemString);
        $encrypted  = $publicKey->encrypt('1234567890');

        $this->assertEquals('1234567890', $privateKey->decrypt($encrypted));
    }

    public function testEncryptionWithPrivateKey()
    {
        $publicKey  = new Rsa\PublicKey($this->testCertificateString);
        $privateKey = new Rsa\PrivateKey($this->testPemString);
        $encrypted  = $privateKey->encrypt('1234567890');

        $this->assertEquals('1234567890', $publicKey->decrypt($encrypted));
    }

    public function testEncryptionWithOwnKeys()
    {
        $encrypted = $this->rsa->encrypt('1234567890');

        $this->assertEquals('1234567890', $this->rsa->decrypt($encrypted));
    }

    public function testEncryptionUsingPublicKeyEncryption()
    {
        $encrypted = $this->rsa->encrypt('1234567890', $this->rsa->getOptions()->getPublicKey());

        $this->assertEquals(
            '1234567890',
            $this->rsa->decrypt($encrypted, $this->rsa->getOptions()->getPrivateKey())
        );
    }

    public function testEncryptionUsingPublicKeyBase64Encryption()
    {
        $encrypted = $this->rsaBase64Out->encrypt('1234567890', $this->rsaBase64Out->getOptions()->getPublicKey());

        $this->assertEquals(
            '1234567890',
            $this->rsaBase64Out->decrypt(
                $encrypted,
                $this->rsaBase64Out->getOptions()->getPrivateKey()
            )
        );
    }

    public function testBase64EncryptionUsingCertificatePublicKeyEncryption()
    {
        $rsa1 = new Rsa(new RsaOptions([
            'public_key'    => new Rsa\PublicKey($this->testCertificateString),
            'binary_output' => false, // output as base 64
        ]));

        $rsa2 = new Rsa(new RsaOptions([
            'private_key'   => new Rsa\PrivateKey($this->testPemString),
            'binary_output' => false, // output as base 64
        ]));

        $encrypted = $rsa1->encrypt('1234567890', $rsa1->getOptions()->getPublicKey());

        $this->assertEquals(
            '1234567890',
            $rsa1->decrypt(base64_decode($encrypted), $rsa2->getOptions()->getPrivateKey())
        );
    }

    public function testEncryptionUsingPrivateKeyEncryption()
    {
        $encrypted = $this->rsa->encrypt('1234567890', $this->rsa->getOptions()->getPrivateKey());
        $decrypted = $this->rsa->decrypt($encrypted, $this->rsa->getOptions()->getPublicKey());

        $this->assertEquals('1234567890', $decrypted);
    }

    public function testEncryptionUsingPrivateKeyBase64Encryption()
    {
        $encrypted = $this->rsaBase64Out->encrypt('1234567890', $this->rsaBase64Out->getOptions()->getPrivateKey());
        $decrypted = $this->rsaBase64Out->decrypt(
            base64_decode($encrypted),
            $this->rsaBase64Out->getOptions()->getPublicKey()
        );

        $this->assertEquals('1234567890', $decrypted);
    }

    public function testKeyGenerationWithDefaults()
    {
        if (! $this->openSslConf) {
            $this->markTestSkipped('No openssl.cnf found or defined; cannot generate keys');
        }

        $rsa = new Rsa();
        $rsa->getOptions()->generateKeys();

        $this->assertInstanceOf(PrivateKey::class, $rsa->getOptions()->getPrivateKey());
        $this->assertInstanceOf(PublicKey::class, $rsa->getOptions()->getPublicKey());
    }

    public function testKeyGenerationWithUserOpensslConfig()
    {
        $rsaOptions = new RsaOptions();
        $rsaOptions->generateKeys([
            'config'           => $this->userOpenSslConf,
            'private_key_bits' => 512,
        ]);

        $this->assertInstanceOf(PrivateKey::class, $rsaOptions->getPrivateKey());
        $this->assertInstanceOf(PublicKey::class, $rsaOptions->getPublicKey());
    }

    public function testKeyGenerationCreatesPassphrasedPrivateKey()
    {
        $this->expectException(Exception\RuntimeException::class);

        $rsaOptions = new RsaOptions([
            'pass_phrase' => '0987654321',
        ]);
        $rsaOptions->generateKeys([
            'config'           => $this->userOpenSslConf,
            'private_key_bits' => 512,
        ]);

        $rsa = Rsa::factory([
            'pass_phrase' => '1234567890',
            'private_key' => $rsaOptions->getPrivateKey()->toString(),
        ]);
    }

    public function testRsaLoadsPassphrasedKeys()
    {
        $this->expectNotToPerformAssertions();

        $rsaOptions = new RsaOptions([
            'pass_phrase' => '0987654321',
        ]);
        $rsaOptions->generateKeys([
            'config'           => $this->userOpenSslConf,
            'private_key_bits' => 512,
        ]);

        Rsa::factory([
            'pass_phrase' => '0987654321',
            'private_key' => $rsaOptions->getPrivateKey()->toString(),
        ]);
    }

    public function testLaminas3492Base64DetectDecrypt()
    {
        $data = 'vNKINbWV6qUKGsmawN8ii0mak7PPNoVQPC7fwXJOgMNfCgdT+9W4PUte4fic6U4A6fMra4gv7NCTESxap2qpBQ==';
        $this->rsa->getOptions()->setOpensslPadding(OPENSSL_PKCS1_PADDING);
        $this->assertEquals('1234567890', $this->rsa->decrypt($data));
    }

    public function testLaminas3492Base64DetectVerify()
    {
        $data = 'sMHpp3u6DNecIm5RIkDD3xyKaH6qqP8roUWDs215iOGHehfK1ypqwoETKNP7NaksGS2C1Up813ixlGXkipPVbQ==';
        $this->assertTrue($this->rsa->verify('1234567890', $data));
    }

    public function testDecryptBase64()
    {
        $data = 'vNKINbWV6qUKGsmawN8ii0mak7PPNoVQPC7fwXJOgMNfCgdT+9W4PUte4fic6U4A6fMra4gv7NCTESxap2qpBQ==';
        $this->rsa->getOptions()->setOpensslPadding(OPENSSL_PKCS1_PADDING);
        $this->assertEquals('1234567890', $this->rsa->decrypt($data, null, Rsa::MODE_BASE64));
    }

    public function testDecryptCorruptBase64()
    {
        $data = 'vNKINbWV6qUKGsmawN8ii0mak7PPNoVQPC7fwXJOgMNfCgdT+9W4PUte4fic6U4A6fMra4gv7NCTESxap2qpBQ==';
        $this->expectException(Exception\RuntimeException::class);
        $this->rsa->decrypt(base64_decode($data), null, Rsa::MODE_BASE64);
    }

    public function testDecryptRaw()
    {
        $data = 'vNKINbWV6qUKGsmawN8ii0mak7PPNoVQPC7fwXJOgMNfCgdT+9W4PUte4fic6U4A6fMra4gv7NCTESxap2qpBQ==';
        $this->rsa->getOptions()->setOpensslPadding(OPENSSL_PKCS1_PADDING);
        $this->assertEquals('1234567890', $this->rsa->decrypt(base64_decode($data), null, Rsa::MODE_RAW));
    }

    public function testDecryptCorruptRaw()
    {
        $data = 'vNKINbWV6qUKGsmawN8ii0mak7PPNoVQPC7fwXJOgMNfCgdT+9W4PUte4fic6U4A6fMra4gv7NCTESxap2qpBQ==';
        $this->expectException(Exception\RuntimeException::class);
        $this->rsa->decrypt($data, null, Rsa::MODE_RAW);
    }

    public function testVerifyBase64()
    {
        $data = 'sMHpp3u6DNecIm5RIkDD3xyKaH6qqP8roUWDs215iOGHehfK1ypqwoETKNP7NaksGS2C1Up813ixlGXkipPVbQ==';
        $this->assertTrue($this->rsa->verify('1234567890', $data, null, Rsa::MODE_BASE64));
    }

    public function testVerifyCorruptBase64()
    {
        $data = 'sMHpp3u6DNecIm5RIkDD3xyKaH6qqP8roUWDs215iOGHehfK1ypqwoETKNP7NaksGS2C1Up813ixlGXkipPVbQ==';
        $this->assertFalse($this->rsa->verify('1234567890', base64_decode($data), null, Rsa::MODE_BASE64));
    }

    public function testVerifyRaw()
    {
        $data = 'sMHpp3u6DNecIm5RIkDD3xyKaH6qqP8roUWDs215iOGHehfK1ypqwoETKNP7NaksGS2C1Up813ixlGXkipPVbQ==';
        $this->assertTrue($this->rsa->verify('1234567890', base64_decode($data), null, Rsa::MODE_RAW));
    }

    public function testVerifyCorruptRaw()
    {
        $data = 'sMHpp3u6DNecIm5RIkDD3xyKaH6qqP8roUWDs215iOGHehfK1ypqwoETKNP7NaksGS2C1Up813ixlGXkipPVbQ==';
        $this->assertFalse($this->rsa->verify('1234567890', $data, null, Rsa::MODE_RAW));
    }
}
