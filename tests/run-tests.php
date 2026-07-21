<?php
/**
 * Plain PHP test runner for the Min side IdP decision matrix.
 *
 * No WordPress, no test framework — run with `php tests/run-tests.php`.
 *
 * @package NettsmedSupport
 */

declare( strict_types=1 );

require __DIR__ . '/../inc/minside-idp-decision.php';

use function Nettsmed\MinsideIdpDecision\decide;

$failures = 0;
$total    = 0;

/**
 * @param array{action:string,reason:string} $expected
 */
function check( string $label, array $expected, ?string $role_claim, bool $user_exists, bool $user_is_admin, bool $autoprovision ): void {
	global $failures, $total;
	$total++;

	$actual = decide( $role_claim, $user_exists, $user_is_admin, $autoprovision );

	if ( $actual === $expected ) {
		echo "PASS: {$label}\n";
		return;
	}

	$failures++;
	echo "FAIL: {$label}\n";
	echo '  expected: ' . json_encode( $expected ) . "\n";
	echo '  actual:   ' . json_encode( $actual ) . "\n";
}

// ── Full matrix for valid roles (owner, member) ─────────────────────────────
// user_exists x user_is_admin x autoprovision, for each valid role.

foreach ( array( 'owner', 'member' ) as $role ) {
	// user_exists=true, admin=true → reject admin-user, regardless of autoprovision.
	check(
		"role={$role} admin-user autoprovision=false",
		array( 'action' => 'reject', 'reason' => 'admin-user' ),
		$role,
		true,
		true,
		false
	);
	check(
		"role={$role} admin-user autoprovision=true",
		array( 'action' => 'reject', 'reason' => 'admin-user' ),
		$role,
		true,
		true,
		true
	);

	// user_exists=true, admin=false → login existing-user, regardless of autoprovision.
	check(
		"role={$role} existing-user autoprovision=false",
		array( 'action' => 'login', 'reason' => 'existing-user' ),
		$role,
		true,
		false,
		false
	);
	check(
		"role={$role} existing-user autoprovision=true",
		array( 'action' => 'login', 'reason' => 'existing-user' ),
		$role,
		true,
		false,
		true
	);

	// user_exists=false, autoprovision=false → reject autoprovision-disabled.
	check(
		"role={$role} no-user autoprovision=false",
		array( 'action' => 'reject', 'reason' => 'autoprovision-disabled' ),
		$role,
		false,
		false,
		false
	);

	// user_exists=false, autoprovision=true → provision.
	check(
		"role={$role} no-user autoprovision=true",
		array( 'action' => 'provision', 'reason' => 'autoprovision' ),
		$role,
		false,
		false,
		true
	);
}

// ── Invalid role claims — fail-closed regardless of other inputs ───────────

$invalid_roles = array( null, 'viewer', 'admin', 'Owner', 'owner ', 'random-string' );

foreach ( $invalid_roles as $role ) {
	$label_role = null === $role ? 'null' : "'{$role}'";

	// Would otherwise login (existing, non-admin user).
	check(
		"invalid role={$label_role} existing-user autoprovision=false",
		array( 'action' => 'reject', 'reason' => 'invalid-role' ),
		$role,
		true,
		false,
		false
	);

	// Would otherwise provision (no user, autoprovision on).
	check(
		"invalid role={$label_role} no-user autoprovision=true",
		array( 'action' => 'reject', 'reason' => 'invalid-role' ),
		$role,
		false,
		false,
		true
	);

	// Would otherwise reject as admin-user — must still be invalid-role, not admin-user.
	check(
		"invalid role={$label_role} admin-user autoprovision=false",
		array( 'action' => 'reject', 'reason' => 'invalid-role' ),
		$role,
		true,
		true,
		false
	);
}

echo "\n{$total} checks, " . ( $total - $failures ) . " passed, {$failures} failed.\n";

if ( $failures > 0 ) {
	exit( 1 );
}

exit( 0 );
