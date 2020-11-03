<?php
namespace JoakimKejser\OAuth;

/**
 * Interface ConsumerStoreInterface.
 */
interface ConsumerStoreInterface
{
	/**
	 * @param string $publicKey
	 *
	 * @return ConsumerInterface
	 */
	public function getConsumer($publicKey);
}
