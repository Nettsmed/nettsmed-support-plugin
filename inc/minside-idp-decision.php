<?php
/**
 * Pure decision logic for Min side IdP login.
 *
 * No WordPress functions — kept testable in plain PHP. Encodes the
 * login / provision / reject matrix so the behaviour can be verified
 * independently of wp-login.php and the REST callback.
 *
 * @package NettsmedSupport
 */

declare( strict_types=1 );

namespace Nettsmed\MinsideIdpDecision;

/**
 * Decide what to do with a Min side IdP login attempt.
 *
 * @return array{action:string,reason:string}
 */
function decide( ?string $role_claim, bool $user_exists, bool $user_is_admin, bool $autoprovision ): array {
	if ( 'owner' !== $role_claim && 'member' !== $role_claim ) {
		return array(
			'action' => 'reject',
			'reason' => 'invalid-role',
		);
	}

	if ( $user_exists && $user_is_admin ) {
		return array(
			'action' => 'reject',
			'reason' => 'admin-user',
		);
	}

	if ( $user_exists ) {
		return array(
			'action' => 'login',
			'reason' => 'existing-user',
		);
	}

	if ( ! $autoprovision ) {
		return array(
			'action' => 'reject',
			'reason' => 'autoprovision-disabled',
		);
	}

	return array(
		'action' => 'provision',
		'reason' => 'autoprovision',
	);
}
