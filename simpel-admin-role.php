<?php
// Create Simpel Admin role
function create_simpel_admin_role() {
    // First remove the role if it exists
    remove_role('simpel_admin');

    // Get the administrator role
    $admin_role = get_role('administrator');
    $admin_capabilities = $admin_role->capabilities;

    // Remove specific capabilities
    $capabilities_to_remove = [
        'activate_plugins', 'delete_plugins', 'edit_plugins', 'install_plugins', 'update_plugins',
        'switch_themes', 'edit_themes', 'delete_themes', 'install_themes', 'update_themes',
        'update_core', 'manage_options'
    ];

    foreach ($capabilities_to_remove as $capability) {
        unset($admin_capabilities[$capability]);
    }

    // Add the Simpel Admin role with the modified capabilities
    add_role(
        'simpel_admin',
        'Simpel Admin',
        $admin_capabilities
    );
}



// Hide Plugins menu for Simpel Admin role
add_action('admin_menu', 'simpel_admin_hide_menu', 9999);
function simpel_admin_hide_menu() {
    $current_user = wp_get_current_user();
    if(in_array('simpel_admin', $current_user->roles)){
        remove_menu_page('plugins.php');
        remove_menu_page('activity-log-page');
        remove_menu_page('tools.php');
        remove_menu_page('jet-dashboard');
        remove_menu_page('options-general.php');
        remove_menu_page('astra');
        remove_menu_page('complianz'); 
        remove_menu_page('wp-mail-smtp'); 
        remove_menu_page('jet-engine'); 
        remove_menu_page('snippets'); 
        remove_menu_page('jet-smart-filters'); 
        remove_menu_page('update-core.php');
        remove_menu_page('activity_log_page'); 
        remove_menu_page('loco'); 
        remove_submenu_page('index.php', 'update-core.php');
        remove_submenu_page('themes.php', 'hello-theme-settings');
        


    }
    
}

add_action('admin_menu', 'simpel_admin_hide_menu');

// Add Analytics menu for Simpel Admin role and Editors
function add_analytics_menu_for_simpel_admin() {
    $current_user = wp_get_current_user();
    
    // Allow access for simpel_admin role OR editor role
    if (in_array('simpel_admin', $current_user->roles) || in_array('editor', $current_user->roles)) {
        // Detect language - check if Norwegian locale is active
        $locale = get_locale();
        $is_norwegian = (strpos($locale, 'nb') === 0 || strpos($locale, 'nn') === 0 || strpos($locale, 'no') === 0);
        $menu_title = $is_norwegian ? 'Analyse' : 'Analytics';
        
        add_menu_page(
            $menu_title,
            $menu_title,
            'edit_posts', // capability
            'index.php?page=plausible_analytics_statistics',
            '',
            'dashicons-chart-bar',
            1 // Position in menu (high priority)
        );
    }
}
add_action('admin_menu', 'add_analytics_menu_for_simpel_admin', 10000);


// The following 2 functions removes all notices with php and css
function simpel_admin_hide_notices() {
    if (!current_user_can('manage_options')) {
        remove_all_actions('admin_notices');
        remove_all_actions('all_admin_notices');
    }
}
add_action('admin_print_scripts', 'simpel_admin_hide_notices', 9999);

function simpel_admin_hide_specific_notices() {
    // Check user capabilities
    if (current_user_can('edit_posts') && !current_user_can('activate_plugins')) {
        echo '<style>
        .notice-warning,
        .e-notice,
        .notice.notice-error,
        .e-notice--dismissible,
        .e-notice--extended,
        li#wp-admin-bar-wp-mail-smtp-menu,
        #menu-dashboard,
        div#screen-options-link-wrap {
            display: none;
        }
        </style>';
    }
}
add_action('admin_head', 'simpel_admin_hide_specific_notices');


// Remove dashboards for simpel admin and lower user roles
function redirect_to_custom_dashboard() {
    global $pagenow;
    
    // Allow access to Plausible Analytics statistics page
    $allowed_pages = array('plausible_analytics_statistics');
    $current_page = isset($_GET['page']) ? $_GET['page'] : '';
    
    // Don't redirect administrators or editors (editors have edit_others_posts capability)
    if (is_admin() && !current_user_can('administrator') && !current_user_can('edit_others_posts') && $pagenow === 'index.php' && 
        (!isset($_GET['page']) || !in_array($current_page, $allowed_pages))) {
        wp_redirect(admin_url('admin.php?page=brukerveiledning'));
        exit();
    }
}


add_action('admin_init', 'redirect_to_custom_dashboard');

// Ensure the simpel_admin role is created when the plugin loads
add_action('init', 'create_simpel_admin_role');

?>
