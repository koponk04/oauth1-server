<?php

use JoakimKejser\OAuth\ConsumerInterface;
use JoakimKejser\OAuth\OauthRequest;
use JoakimKejser\OAuth\Util;
use PHPUnit\Framework\TestCase;

class UtilTest extends TestCase
{
	public function testUrlencodeRfc3986(): void
	{
		$this->markTestIncomplete('This test has not been implemented yet.');
	}

	public function testUrlDecodeRfc3986(): void
	{
		$this->markTestIncomplete('This test has not been implemented yet.');
	}

	public function testSplitHeader(): void
	{
		$consumer = new Consumer(['key' => 'key', 'secret' => 'secret']);
		$request = OauthRequest::createFromConsumerAndToken($consumer, 'GET', 'http://localhost/index.php');
		$request->sign(new JoakimKejser\OAuth\SignatureMethod\HmacSha1(), $consumer);

		$headers = Util::splitHeader($request->toHeader());

		$this->assertEquals($request->getParameter('oauth_signature'), $headers['oauth_signature']);
		$this->assertEquals($request->getParameter('oauth_signature_method'), $headers['oauth_signature_method']);
		$this->assertEquals($request->getParameter('oauth_consumer_key'), $headers['oauth_consumer_key']);
		$this->assertEquals($request->getParameter('oauth_nonce'), $headers['oauth_nonce']);
		$this->assertEquals($request->getParameter('oauth_timestamp'), $headers['oauth_timestamp']);
	}

	public function testGetHeaders(): void
	{
		$this->markTestIncomplete('This test has not been implemented yet.');
	}

	public function testParseParameters(): void
	{
		$this->markTestIncomplete('This test has not been implemented yet.');
	}

	public function testBuildHttpQuery(): void
	{
		$this->markTestIncomplete('This test has not been implemented yet.');
	}
}

if (!class_exists('Consumer')) {
	class Consumer implements ConsumerInterface
	{
		protected $data;

		public function __construct(array $data)
		{
			$this->data = $data;
		}

		public function getValue($field)
		{
			if (isset($this->data[$field])) {
				return $this->data[$field];
			}

			return null;
		}

		public function getKey()
		{
			return $this->getValue('key');
		}

		public function getSecret()
		{
			return $this->getValue('secret');
		}
	}
}
