<?php
/**
 * Nora — context-aware AI help drawer in wp-admin.
 *
 * Enqueues the shared Nettsmed chat widget (hjelp.nettsmed.no) across wp-admin,
 * passing the current admin screen id and the site's detected stack so the
 * drawer surfaces screen-aware suggestions and weights its answers. The drawer
 * serves public help content, so no auth/token crosses the iframe — the plugin
 * only reports context.
 *
 * @package Nettsmed\Support
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'NETTSMED_HELP_BASE' ) ) {
	// Overridable per-site via wp-config (e.g. a staging help center).
	define( 'NETTSMED_HELP_BASE', 'https://hjelp.nettsmed.no' );
}

/**
 * Detect the active stack as a comma-separated list matching hjelp.nettsmed.no's
 * HelpStack vocabulary: wordpress | elementor | gutenberg | woocommerce | generell.
 *
 * @return string CSV of detected stacks (always includes 'wordpress').
 */
function nettsmed_help_detect_stack() {
	if ( ! function_exists( 'is_plugin_active' ) ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
	}

	$stack = array( 'wordpress' );

	if ( is_plugin_active( 'woocommerce/woocommerce.php' ) ) {
		$stack[] = 'woocommerce';
	}

	if ( is_plugin_active( 'elementor/elementor.php' ) || is_plugin_active( 'elementor-pro/elementor-pro.php' ) ) {
		$stack[] = 'elementor';
	}

	// Block editor (Gutenberg) — only meaningful on an editor screen.
	$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
	if ( $screen && method_exists( $screen, 'is_block_editor' ) && $screen->is_block_editor() ) {
		$stack[] = 'gutenberg';
	}

	return implode( ',', array_unique( $stack ) );
}

/**
 * Enqueue the help widget on admin pages, tagged with the current screen + stack.
 *
 * @return void
 */
function nettsmed_help_enqueue_drawer() {
	if ( ! is_user_logged_in() ) {
		return;
	}

	$screen    = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
	$screen_id = $screen ? (string) $screen->id : '';
	$stack     = nettsmed_help_detect_stack();

	$src = trailingslashit( NETTSMED_HELP_BASE ) . 'widget.js';

	// Version null → no ?ver= query; the widget loader pins itself.
	wp_enqueue_script( 'nettsmed-help-widget', $src, array(), null, true );

	// The widget.js loader is data-* driven; inject the attributes onto its tag.
	add_filter(
		'script_loader_tag',
		function ( $tag, $handle ) use ( $screen_id, $stack ) {
			if ( 'nettsmed-help-widget' !== $handle ) {
				return $tag;
			}
			$attrs = sprintf(
				' data-base="%s" data-label="%s" data-aria="%s" data-title="%s" data-initial="N" data-screen="%s" data-stack="%s"',
				esc_url( NETTSMED_HELP_BASE ),
				esc_attr__( 'Hjelp', 'nettsmed-support' ),
				esc_attr__( 'Åpne hjelp', 'nettsmed-support' ),
				esc_attr__( 'Nettsmed hjelp', 'nettsmed-support' ),
				esc_attr( $screen_id ),
				esc_attr( $stack )
			);
			return str_replace( ' src=', $attrs . ' src=', $tag );
		},
		10,
		2
	);
}
add_action( 'admin_enqueue_scripts', 'nettsmed_help_enqueue_drawer' );
