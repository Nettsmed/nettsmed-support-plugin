<?php
/**
 * Admin Dashboard Settings
 * Allows administrators to configure embed content and menu title
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Add admin menu for dashboard settings (only for administrators)
function add_admin_dashboard_settings_menu() {
    $current_user = wp_get_current_user();
    
    // Only show to full administrators, not simple admins
    if (in_array('simpel_admin', $current_user->roles)) {
        return; // This is a simple admin, don't show the settings
    }
    
    if (current_user_can('administrator')) {
        add_options_page(
            'Dashboard Settings',
            'Dashboard Settings',
            'administrator',
            'admin-dashboard-settings',
            'admin_dashboard_settings_page'
        );
    }
}
add_action('admin_menu', 'add_admin_dashboard_settings_menu');

// Register settings
function register_admin_dashboard_settings() {
    register_setting('admin_dashboard_settings', 'admin_dashboard_embed_code');
    register_setting('admin_dashboard_settings', 'admin_dashboard_menu_title');
}
add_action('admin_init', 'register_admin_dashboard_settings');

// Settings page content
function admin_dashboard_settings_page() {
    if (!current_user_can('administrator')) {
        wp_die(__('You do not have sufficient permissions to access this page.'));
    }
    
    $embed_code = get_option('admin_dashboard_embed_code', '');
    $menu_title = get_option('admin_dashboard_menu_title', '');
    
    ?>
    <div class="wrap">
        <h1>Dashboard Settings</h1>
        <p>Configure the embed content and menu title for the admin dashboard.</p>
        
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

// Add dynamic menu item for simple admins
function add_dynamic_menu_for_simple_admins() {
    $current_user = wp_get_current_user();
    
    // Only add menu for simple admins
    if (in_array('simpel_admin', $current_user->roles)) {
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
add_action('admin_menu', 'add_dynamic_menu_for_simple_admins');

// Display the embed page
function display_embed_page() {
    $current_user = wp_get_current_user();
    
    // Check if user is simple admin
    if (!in_array('simpel_admin', $current_user->roles)) {
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
    
    // Only add script for simple admins
    if (in_array('simpel_admin', $current_user->roles)) {
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
?>
