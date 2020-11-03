<?php
namespace JoakimKejser\OAuth;

/**
 * Interface NonceStore
 * @package JoakimKejser\OAuth
 */
interface NonceStoreInterface
{
    /**
     * * Lookup at nonce and if it doesn't exist save it
     * @param ConsumerInterface $consumer
     * @param string $nonce
     * @param int $timestamp
     * @param TokenInterface $token
     * @return string
     */
    public function lookup(ConsumerInterface $consumer, $nonce, $timestamp, TokenInterface $token = null);
}
