<?php /** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace SiViN\Crypt\Tests;

use SiViN\Crypt\Exception\KeyNotFoundException;
use SiViN\Crypt\Exception\WrongKeyException;
use SiViN\Crypt\Tests\Fixtures\BaseTestCase;
use Tester\Assert;
use Tester\Expect;

require_once __DIR__ . '/../bootstrap.php';

class CryptRsaTest extends BaseTestCase
{
	private $str = 'Lorem ipsum dolor sit amet, consectetuer adipiscing elit. In enim a arcu imperdiet malesuada.';
	
	public function testCreateKeyPair()
	{
		$rsa = $this->getCryptService();
		$keys = $rsa->createKeyPair();
		Assert::equal([ 'privateKeyRaw' => Expect::type('string'), 'publicKeyRaw' => Expect::type('string') ], $keys);
	}
	
	public function testEncryptDecrypt()
	{
		$crypt = $this->getCryptService();
		
		Assert::exception(function ()use($crypt){
			$crypt->setPublicKey('wrong key');
			$crypt->encryptRsa($this->str);
		}, WrongKeyException::class);
		
		Assert::exception(function ()use($crypt){
			$crypt->setPublicKey('');
			$crypt->encryptRsa($this->str);
		}, KeyNotFoundException::class);
		
		$keys = $crypt->createKeyPair();
		$crypt->setPublicKey($keys['publicKeyRaw']);
		$crypt->setPrivateKey($keys['privateKeyRaw']);
		
		$cipherStr = $crypt->encryptRsa($this->str);
		Assert::false(strcmp($this->str, $cipherStr) === 0);
		
		$str = $crypt->decryptRsa($cipherStr);
		Assert::equal($this->str, $str);
	}
	
	public function testEncryptDecryptWithPassword()
	{
		$rsa = $this->getCryptService();
		$keys = $rsa->createKeyPair('pass');
		$rsa->setPublicKey($keys['publicKeyRaw']);
		$rsa->setPrivateKey($keys['privateKeyRaw']);
		
		$cipherStr = $rsa->encryptRsa($this->str);
		Assert::false(strcmp($this->str, $cipherStr) === 0);
		
		$rsa->setPrivateKeyPassword('pass');
		$str = $rsa->decryptRsa($cipherStr);
		Assert::equal($this->str, $str);
		
		$rsa->setPrivateKeyPassword('wrong');
		Assert::exception(function () use($rsa, $cipherStr) {
			$rsa->decryptRsa($cipherStr);
		}, WrongKeyException::class);
	}
	
}

(new CryptRsaTest)->run();
