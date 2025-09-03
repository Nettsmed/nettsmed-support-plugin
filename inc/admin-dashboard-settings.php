<?php
/**
 * Admin Dashboard Settings
 * Allows administrators to configure embed content and menu title
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Add Nettsmed admin menu (only for administrators)
function add_nettsmed_admin_menu() {
    $current_user = wp_get_current_user();
    
    // Only show to full administrators, not simple admins
    if (in_array('simpel_admin', $current_user->roles)) {
        return; // This is a simple admin, don't show the menu
    }
    
    if (current_user_can('administrator')) {
        // Add main Nettsmed admin menu
        add_menu_page(
            'Nettsmed Admin',
            'Nettsmed Admin',
            'administrator',
            'nettsmed-admin',
            'nettsmed_admin_dashboard_page',
            'dashicons-admin-tools',
            3 // Position in menu
        );
        
        // Add Dashboard Settings as submenu
        add_submenu_page(
            'nettsmed-admin',
            'Dashboard Settings',
            'Dashboard Settings',
            'administrator',
            'admin-dashboard-settings',
            'admin_dashboard_settings_page'
        );
    }
}
add_action('admin_menu', 'add_nettsmed_admin_menu');

// Register settings
function register_admin_dashboard_settings() {
    register_setting('admin_dashboard_settings', 'admin_dashboard_embed_code');
    register_setting('admin_dashboard_settings', 'admin_dashboard_menu_title');
    register_setting('admin_dashboard_settings', 'disable_2fa_simple_admin');
}
add_action('admin_init', 'register_admin_dashboard_settings');

// Main Nettsmed admin dashboard page
function nettsmed_admin_dashboard_page() {
    if (!current_user_can('administrator')) {
        wp_die(__('You do not have sufficient permissions to access this page.'));
    }
    
    $embed_code = get_option('admin_dashboard_embed_code', '');
    $menu_title = get_option('admin_dashboard_menu_title', '');
    $disable_2fa = get_option('disable_2fa_simple_admin', 1);
    
    ?>
    <div class="wrap">
        <h1>Nettsmed Admin Dashboard</h1>
        <p>Welcome to the Nettsmed admin panel. Here you can manage various settings for your WordPress site.</p>
        
        <div class="nettsmed-admin-overview">
            <h2>Quick Overview</h2>
            <div class="nettsmed-admin-cards">
                <div class="nettsmed-admin-card">
                    <h3>Dashboard Settings</h3>
                    <p>Configure embed content and menu titles for simple admins.</p>
                    <a href="<?php echo admin_url('admin.php?page=admin-dashboard-settings'); ?>" class="button button-primary">Configure Settings</a>
                </div>
                
                <?php if (!empty($embed_code) && !empty($menu_title)): ?>
                <div class="nettsmed-admin-card">
                    <h3>Current Configuration</h3>
                    <p><strong>Menu Title:</strong> <?php echo esc_html($menu_title); ?></p>
                    <p><strong>Embed Code:</strong> <?php echo !empty($embed_code) ? 'Configured' : 'Not set'; ?></p>
                    <p class="description">Simple admins will see a menu item called "<?php echo esc_html($menu_title); ?>" that opens the embed page in a new tab.</p>
                </div>
                <?php else: ?>
                <div class="nettsmed-admin-card">
                    <h3>Setup Required</h3>
                    <p>Configure the dashboard settings to enable the embed functionality for simple admins.</p>
                    <a href="<?php echo admin_url('admin.php?page=admin-dashboard-settings'); ?>" class="button">Setup Now</a>
                </div>
                <?php endif; ?>
                
                <div class="nettsmed-admin-card">
                    <h3>Security Settings</h3>
                    <p><strong>2FA for Simple Admins:</strong> 
                        <?php if ($disable_2fa): ?>
                            <span class="status-disabled">Disabled</span> - Simple admins can log in without 2FA
                        <?php else: ?>
                            <span class="status-enabled">Enabled</span> - Simple admins must use 2FA
                        <?php endif; ?>
                    </p>
                    <p class="description">
                        <?php if (class_exists('ITSEC_Core')): ?>
                            Solid Security plugin detected. 2FA bypass is <?php echo $disable_2fa ? 'active' : 'inactive'; ?>.
                        <?php else: ?>
                            Solid Security plugin not detected. This setting will take effect when the plugin is installed.
                        <?php endif; ?>
                    </p>
                    <a href="<?php echo admin_url('admin.php?page=admin-dashboard-settings'); ?>" class="button">Configure Security</a>
                </div>
            </div>
        </div>
        
        <div class="nettsmed-admin-section">
            <h2>Simple Admin Users</h2>
            <div class="simple-admin-list">
                <?php
                // Get all users with simpel_admin role
                $simple_admins = get_users(array('role' => 'simpel_admin'));
                
                if (!empty($simple_admins)) {
                    echo '<table class="wp-list-table widefat fixed striped">';
                    echo '<thead><tr><th>Username</th><th>Display Name</th><th>Email</th><th>Last Login</th><th>Status</th></tr></thead>';
                    echo '<tbody>';
                    
                    foreach ($simple_admins as $user) {
                        $last_login = get_user_meta($user->ID, 'last_login', true);
                        $last_login_formatted = $last_login ? date('Y-m-d H:i:s', $last_login) : 'Never';
                        $is_online = (get_user_meta($user->ID, 'last_activity', true) > (time() - 300)); // 5 minutes
                        $status = $is_online ? '<span class="status-online">Online</span>' : '<span class="status-offline">Offline</span>';
                        
                        echo '<tr>';
                        echo '<td><strong>' . esc_html($user->user_login) . '</strong></td>';
                        echo '<td>' . esc_html($user->display_name) . '</td>';
                        echo '<td>' . esc_html($user->user_email) . '</td>';
                        echo '<td>' . esc_html($last_login_formatted) . '</td>';
                        echo '<td>' . $status . '</td>';
                        echo '</tr>';
                    }
                    
                    echo '</tbody></table>';
                } else {
                    echo '<p>No simple admin users found.</p>';
                }
                ?>
            </div>
        </div>
    </div>
    
    <style>
    .nettsmed-admin-overview {
        margin-top: 20px;
    }
    .nettsmed-admin-cards {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
        gap: 20px;
        margin-top: 20px;
    }
    .nettsmed-admin-card {
        background: #fff;
        border: 1px solid #ccd0d4;
        border-radius: 4px;
        padding: 20px;
        box-shadow: 0 1px 1px rgba(0,0,0,.04);
    }
    .nettsmed-admin-card h3 {
        margin-top: 0;
        color: #23282d;
    }
    .nettsmed-admin-card p {
        margin-bottom: 15px;
    }
    .nettsmed-admin-card .button {
        margin-top: 10px;
    }
    .nettsmed-admin-section {
        margin-top: 30px;
        background: #fff;
        border: 1px solid #ccd0d4;
        border-radius: 4px;
        padding: 20px;
        box-shadow: 0 1px 1px rgba(0,0,0,.04);
    }
    .nettsmed-admin-section h2 {
        margin-top: 0;
        color: #23282d;
        border-bottom: 1px solid #eee;
        padding-bottom: 10px;
    }
    .simple-admin-list table {
        margin-top: 15px;
    }
    .simple-admin-list th {
        font-weight: 600;
        background: #f9f9f9;
    }
    .status-online {
        color: #46b450;
        font-weight: 600;
    }
    .status-offline {
        color: #dc3232;
        font-weight: 600;
    }
    .status-disabled {
        color: #46b450;
        font-weight: 600;
    }
    .status-enabled {
        color: #dc3232;
        font-weight: 600;
    }
    </style>
    <?php
}

// Settings page content
function admin_dashboard_settings_page() {
    if (!current_user_can('administrator')) {
        wp_die(__('You do not have sufficient permissions to access this page.'));
    }
    
    $embed_code = get_option('admin_dashboard_embed_code', '');
    $menu_title = get_option('admin_dashboard_menu_title', '');
    $disable_2fa = get_option('disable_2fa_simple_admin', 1); // Default to enabled
    
    ?>
    <div class="wrap">
        <h1>Dashboard Settings</h1>
        <p>Configure the embed content, menu title, and security settings for the admin dashboard.</p>
        
        <form method="post" action="options.php">
            <?php settings_fields('admin_dashboard_settings'); ?>
            <?php do_settings_sections('admin_dashboard_settings'); ?>
            
            <table class="form-table">
                <tr>
                    <th scope="row">
                        <label for="admin_dashboard_menu_title">Menu Title</label>
                    </th>
                    <td>
                        <input type="text" 
                               id="admin_dashboard_menu_title" 
                               name="admin_dashboard_menu_title" 
                               value="<?php echo esc_attr($menu_title); ?>" 
                               class="regular-text" 
                               placeholder="Enter menu title for simple admins" />
                        <p class="description">This title will appear in the wp-admin sidebar for simple admins.</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="admin_dashboard_embed_code">Embed Code</label>
                    </th>
                    <td>
                        <textarea id="admin_dashboard_embed_code" 
                                  name="admin_dashboard_embed_code" 
                                  rows="10" 
                                  cols="50" 
                                  class="large-text code" 
                                  placeholder="Enter your embed code here (e.g., iframe)"><?php echo esc_textarea($embed_code); ?></textarea>
                        <p class="description">Enter the embed code that will be displayed on the embed page. This will open in a new tab when clicked.</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="disable_2fa_simple_admin">Security Settings</label>
                    </th>
                    <td>
                        <label>
                            <input type="checkbox" 
                                   id="disable_2fa_simple_admin" 
                                   name="disable_2fa_simple_admin" 
                                   value="1" 
                                   <?php checked($disable_2fa, 1); ?> />
                            Disable 2FA for Simple Admin users
                        </label>
                        <p class="description">When enabled, Simple Admin users will not be required to use Two-Factor Authentication (2FA) when Solid Security plugin is active. This setting is enabled by default for easier access.</p>
                    </td>
                </tr>
            </table>
            
            <?php submit_button(); ?>
        </form>
        
        <?php if (!empty($embed_code) && !empty($menu_title)): ?>
        <div class="notice notice-info">
            <p><strong>Preview:</strong> Simple admins will see a menu item called "<strong><?php echo esc_html($menu_title); ?></strong>" that will open the embed page in a new tab.</p>
        </div>
        <?php endif; ?>
    </div>
    <?php
}

// Add dynamic menu item for simple admins and administrators
function add_dynamic_menu_for_users() {
    $current_user = wp_get_current_user();
    
    // Add menu for both simple admins and full administrators
    if (in_array('simpel_admin', $current_user->roles) || current_user_can('administrator')) {
        $menu_title = get_option('admin_dashboard_menu_title', '');
        $embed_code = get_option('admin_dashboard_embed_code', '');
        
        // Only add menu if both title and embed code are set
        if (!empty($menu_title) && !empty($embed_code)) {
            add_menu_page(
                $menu_title,
                $menu_title,
                'edit_posts',
                'admin-dashboard-embed',
                'display_embed_page',
                'dashicons-external',
                2 // Position in menu
            );
        }
    }
}
add_action('admin_menu', 'add_dynamic_menu_for_users');

// Display the embed page
function display_embed_page() {
    $current_user = wp_get_current_user();
    
    // Check if user is simple admin or full administrator
    if (!in_array('simpel_admin', $current_user->roles) && !current_user_can('administrator')) {
        wp_die(__('You do not have sufficient permissions to access this page.'));
    }
    
    $embed_code = get_option('admin_dashboard_embed_code', '');
    
    if (empty($embed_code)) {
        echo '<div class="wrap"><h1>No embed content configured</h1><p>Please contact an administrator to configure the embed content.</p></div>';
        return;
    }
    
    ?>
    <div class="wrap">
        <h1><?php echo esc_html(get_option('admin_dashboard_menu_title', 'Dashboard')); ?></h1>
        <div class="embed-container">
            <?php echo wp_kses($embed_code, array(
                'iframe' => array(
                    'src' => array(),
                    'width' => array(),
                    'height' => array(),
                    'frameborder' => array(),
                    'allowfullscreen' => array(),
                    'title' => array(),
                    'style' => array(),
                    'class' => array(),
                    'id' => array()
                )
            )); ?>
        </div>
    </div>
    
    <style>
    .embed-container {
        margin-top: 20px;
        border: 1px solid #ddd;
        border-radius: 4px;
        overflow: hidden;
    }
    .embed-container iframe {
        width: 100%;
        min-height: 600px;
        border: none;
    }
    </style>
    <?php
}

// Add JavaScript to open embed page in new tab
function add_embed_page_script() {
    $current_user = wp_get_current_user();
    
    // Add script for both simple admins and full administrators
    if (in_array('simpel_admin', $current_user->roles) || current_user_can('administrator')) {
        $menu_title = get_option('admin_dashboard_menu_title', '');
        $embed_code = get_option('admin_dashboard_embed_code', '');
        
        // Only add script if both title and embed code are set
        if (!empty($menu_title) && !empty($embed_code)) {
            ?>
            <script type="text/javascript">
            jQuery(document).ready(function($) {
                // Find the menu item and make it open in new tab
                $('a[href*="admin-dashboard-embed"]').attr('target', '_blank');
            });
            </script>
            <?php
        }
    }
}
add_action('admin_footer', 'add_embed_page_script');

// Track user login times
function track_user_login($user_login, $user) {
    update_user_meta($user->ID, 'last_login', time());
    update_user_meta($user->ID, 'last_activity', time());
}
add_action('wp_login', 'track_user_login', 10, 2);

// Track user activity (heartbeat)
function track_user_activity() {
    if (is_user_logged_in()) {
        $user_id = get_current_user_id();
        update_user_meta($user_id, 'last_activity', time());
    }
}
add_action('wp_ajax_heartbeat', 'track_user_activity');
add_action('wp_ajax_nopriv_heartbeat', 'track_user_activity');

// Track admin page visits
function track_admin_activity() {
    if (is_admin() && is_user_logged_in()) {
        $user_id = get_current_user_id();
        update_user_meta($user_id, 'last_activity', time());
    }
}
add_action('admin_init', 'track_admin_activity');

// Solid Security 2FA Exception for Simpel Admin
function ns_disable_2fa_for_simpel_admin($providers, $user) {
    // Check if the setting is enabled
    $disable_2fa_setting = get_option('disable_2fa_simple_admin', 1);
    
    if ($disable_2fa_setting && $user instanceof WP_User && in_array('simpel_admin', (array)$user->roles, true)) {
        return []; // no providers => no 2FA
    }
    return $providers;
}

// Only add the filters if Solid Security is active
if (class_exists('ITSEC_Core')) {
    add_filter('itsec_two_factor_allowed_providers_for_user', 'ns_disable_2fa_for_simpel_admin', 10, 2);
    add_filter('itsec_two_factor_available_providers_for_user', 'ns_disable_2fa_for_simpel_admin', 10, 2);
}
?>
