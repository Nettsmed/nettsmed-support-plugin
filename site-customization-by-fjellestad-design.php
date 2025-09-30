<?php
/**
* Plugin Name: Site Customization by Nettsmed
* Plugin URI: https://nettsmed.no
* Description: Site customization plugin for Nettsmed customers. 
 * Version: 1.2.5
* Author: Sindre Fjellestad
* Author URI: https://github.com/Sinfjell
*/

require 'kernl-update-checker/kernl-update-checker.php';
$MyUpdateChecker = Puc_v4_Factory::buildUpdateChecker(
    'https://kernl.us/api/v1/updates/646b94421a29b03ad5288e84/',
    __FILE__,
    'site-customizer-by-fjellestad-design'
);

// Include your PHP files
require plugin_dir_path(__FILE__) . 'fjellestad-support-backend-widget.php';
require plugin_dir_path(__FILE__) . 'remove-dashboard-widgets.php';
require plugin_dir_path(__FILE__) . 'simpel-admin-role.php';
require plugin_dir_path(__FILE__) . 'inc/admin-dashboard-settings.php';

register_activation_hook( __FILE__, 'create_simpel_admin_role' );

require_once plugin_dir_path(__FILE__) . 'custom-dashboard.php';

?>
