<?php

class NettsmedSentry {

	private const DSN_CONSTANT = 'NETTSMED_SUPPORT_SENTRY_DSN';
	private const PLUGIN_DIR = 'nettsmed-support-plugin';
	private const VERSION = '1.3.0';

	public static function init(): void {
		if ( ! defined( self::DSN_CONSTANT ) || empty( constant( self::DSN_CONSTANT ) ) ) {
			return;
		}

		if ( ! class_exists( '\Sentry\SentrySdk' ) ) {
			return;
		}

		\Sentry\init( [
			'dsn'         => constant( self::DSN_CONSTANT ),
			'environment' => wp_parse_url( home_url(), PHP_URL_HOST ),
			'release'     => self::VERSION,
			'before_send' => [ self::class, 'filter_event' ],
		] );
	}

	public static function filter_event( \Sentry\Event $event, ?\Sentry\EventHint $hint ): ?\Sentry\Event {
		$exceptions = $event->getExceptions();

		foreach ( $exceptions as $exception ) {
			$stacktrace = $exception->getStacktrace();
			if ( $stacktrace === null ) {
				continue;
			}

			foreach ( $stacktrace->getFrames() as $frame ) {
				$file = $frame->getFile();
				if ( $file !== null && str_contains( $file, self::PLUGIN_DIR . '/' ) ) {
					return $event;
				}
			}
		}

		return null;
	}
}
