<?php /** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace SiViN\Crypt\Tests\Crypt;

use SiViN\Crypt\Exception\DecryptException;
use SiViN\Crypt\Tests\Fixtures\BaseTestCase;
use Tester\Assert;

require_once __DIR__ . '/../bootstrap.php';

class CryptMessageTest extends BaseTestCase
{
	
	private $str = 'Lorem ipsum dolor sit amet, consectetuer adipiscing elit. In enim a arcu imperdiet malesuada.';
	
	public function testCompleteTransport()
	{
		$crypt = $this->getCryptService();
		$keys = $crypt->createKeyPair();
		$crypt->setPublicKey($keys['publicKeyRaw']);
		$crypt->setPrivateKey($keys['privateKeyRaw']);
		
		$messageEnc = $crypt->encryptRijndaelMessage($this->str);
		$str = $crypt->decryptRijndaelMessage($messageEnc);
		Assert::equal($str, $this->str);
	}
	
	public function testDecrypt()
	{
		$crypt = $this->getCryptService();
		
		$keysDir = __DIR__ . implode(DIRECTORY_SEPARATOR, [ '', '..', '..', 'keys' ]);
		$crypt->setPublicKey(file_get_contents($keysDir . DIRECTORY_SEPARATOR . 'public.key'));
		$crypt->setPrivateKey(file_get_contents($keysDir . DIRECTORY_SEPARATOR . 'private.key'));
		
		$str = $crypt->decryptRijndaelMessage('158eQ5nKAu6AANh4fTkwNEsWazYKpShsWClI+9YR4aOM1IxqLpslii0Pqq5ZykUJFH3jzQgOFenW0MRduRlUiFxV1Gh3RIJm3ftTXm2OkoabwDr8N9CJ8gLqfE5/Zbg5nw5j0YiGtN/R6xTSsuTItWfnzw9VgJKfsTp9U+vnTUuTBXa/smKSLiCyw3mhV/R7WpL1G8iZDYqGrc9S542VlEShPkz418ABKVBptZFHEWM8yAMDd6vCPdX62XAELZGnS2s43gSkoYsKHcxGDi4SHYQHD/x6LgiFJUxAaIMxejOC90I7gyzkh7ZjXjfiAnelVaEYJen+1xrO1TZjALlafLq9A==nvfQ3tl4mP6LvIHUvxytgWkrqPCK7YOLKWfAW2eXU1xoPp/9KRiadXnGWKeeH27BTWXNh0TTGpoUO6uN0B0fwa8vW9zK3ZHMMLx/wlP9U9lNf2s6nechbrERZ5u1YcCPRPw97JKFmHuEFIohK6JgpTv5n9l7gS9ZXXLSE/XqBpoZNS8Qg9fpWF4ZMvFpyhNO4ATM1s0udRL3bWvfG8RjvCtcNtJaAZeiutRtGJB5dqjifgwog9TlmMh8hLZ9g3SN1r2BhEsc2gi/HUPMNOe+NT43+39A/JUQwCCwWLOH5sbStzOBwLI1boWImYzQ/d/AQMOj1LDF1W3G6H+7ooWNGHsxivZXzQey9/Fsad5suZmVoGJ9J+f7Le7rgYqKKXEHUrVtL69G1WBOjkUNQUZdbqyRk+yEYjsS2r1AJRceRsRRUUlJqn8UByw+2OuLLLxkRdV/t0A8wnBi7K5YpIuceA==');
		$path = __DIR__ . DIRECTORY_SEPARATOR . 'input' . DIRECTORY_SEPARATOR . 'CryptMessageTest.[testDecrypt].json';
		Assert::equal(file_get_contents($path), $str);
		
		Assert::exception(function () use ($crypt){
			$crypt->decryptRijndaelMessage('failmessage');
		}, DecryptException::class);
		
		Assert::exception(function () use ($crypt){
			$crypt->decryptRijndaelMessage('');
		}, DecryptException::class);
		
	}
	
}

(new CryptMessageTest())->run();
