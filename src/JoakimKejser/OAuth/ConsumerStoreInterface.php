<?php
namespace JoakimKejser\OAuth;

/**
 * Interface ConsumerStoreInterface
 * @package JoakimKejser\OAuth
 */
interface ConsumerStoreInterface
{
    /**
     * @param string $publicKey
     * @return ConsumerInterface
     */
    public function getConsumer($publicKey);
}
