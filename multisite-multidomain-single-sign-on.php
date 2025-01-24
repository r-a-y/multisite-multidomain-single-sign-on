<?php
/*
Plugin Name: Multisite Multidomain Single Sign On
Description: Automatically sign the user in to separate-domain sites of the same multisite installation, when switching sites using the 'My Sites' links in the admin menu. Note that the user already has to be logged into a site in the network, this plugin just cuts down on having to log in again due to cookie isolation between domains. Note: This plugin must be installed on all sites in a network in order to work.
Version: 1.3.9
Requires at least: 5.0
Tested up to: 5.7.2
Requires PHP: 7.4
Author: emfluence Digital Marketing
Author URI: https://emfluence.com
License: GPL2
*/

const MMSSO_FROM_QUERY_VAR      = 'sso-f';
const MMSSO_RETURN_TO_QUERY_VAR = 'sso-r';
const MMSSO_NONCE               = 'sso-n';
const MMSSO_HASH_QUERY_VAR      = 'sso-h';
const MMSSO_USER_ID_QUERY_VAR   = 'sso-u';
const MMSSO_EXPIRES_QUERY_VAR   = 'sso-e';
const MMSSO_NONCE_PREFIX        = 'mmsso-';

/** @noinspection AutoloadingIssuesInspection */

class Multisite_Multidomain_Single_Sign_On {

	/**
	 *  Store the singleton instance
	 *
	 * @var  Multisite_Multidomain_Single_Sign_On
	 */
	protected static $instance;

	/**
	 * Create singleton instance.
	 *
	 * @return Multisite_Multidomain_Single_Sign_On
	 */
	public static function get_instance() : Multisite_Multidomain_Single_Sign_On {
		if ( ! self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}


	/**
	 * Private constructor. We can only be constructed via the get_instance method.
	 */
	private function __construct() {
		add_action( 'wp_before_admin_bar_render', [ $this, 'change_site_switcher_links' ] );
		add_action( 'init', [ $this, 'receive_sso_request' ] );
		add_action( 'init', [ $this, 'authorize_request' ] );
		add_action( 'init', [ $this, 'receive_auth' ] );
	}

	/**
	 * Change the links in the admin menu bar
	 *
	 * @see WP_Admin_Bar
	 * @see wp_admin_bar_my_sites_menu()
	 */
	public function change_site_switcher_links() : void {
		global $wp_admin_bar;
		$nodes           = $wp_admin_bar->get_nodes();
		$current_site_id = get_current_blog_id();
		$current_site    = get_site( $current_site_id );
		foreach ( $nodes as $id => $node ) {

			if ( empty( $node->href ) ) {
				continue;
			}

			$is_site_node          = ( 0 === stripos( $id, 'blog' ) );
			$is_network_admin_node = ( 0 === stripos( $id, 'network-admin' ) );

			if ( ! ( $is_site_node || $is_network_admin_node ) ) {
				continue;
			}

			if ( in_array( $current_site->domain, explode( '/', $node->href ), true ) ) {
				continue;
			}

			$node->href = $this->add_sso_to_url( $node->href );
			$wp_admin_bar->add_node( $node );
		}
	}

	/**
	 * Add Single Sign-on parameters to the passed in URL.
	 *
	 * @param string $url The passed in URL.
	 *
	 * @return string The url with added parameters.
	 */
	public function add_sso_to_url( string $url ) : string {
		$current_site_id  = get_current_blog_id();
		$target_url_parts = wp_parse_url( $url );
		if ( $target_url_parts === false || $target_url_parts === null || empty( $target_url_parts['host'] ) ) {

			return $url;
		}
		$site = get_site( $current_site_id );
		if ( $target_url_parts['host'] === $site->domain ) {

			return $url;
		}
		$target_site = get_site_by_path( $target_url_parts['host'], $target_url_parts['path'] ?? '/' );
		if ( $target_site === false ) {
			return $url;
		}

		// Add support for Mercator aliases.
		if ( defined( '\Mercator\VERSION' ) ) {
			// See if the target site is mapped.
			$mapping = self::get_mercator_alias( $target_site->id );

			// We're using a mapped domain.
			if ( false !== $mapping ) {
				// Don't do this if we're already on the mapped domain.
				if ( $current_site_id === $mapping->get_site_id() ) {
					return $url;
				}

				// Set the target host to use the alias domain.
				$target_url_parts['host'] = $mapping->get_domain();
			}
		}

		// Set URL again.
		$url = sprintf( '%1$s://%2$s%3$s', $target_url_parts['scheme'], $target_url_parts['host'], $target_url_parts['path'] );

		$nonce = wp_create_nonce( MMSSO_NONCE_PREFIX . $current_site_id . '-' . $target_site->blog_id );

		return add_query_arg(
			[
				MMSSO_FROM_QUERY_VAR => $current_site_id,
				MMSSO_NONCE          => $nonce,
			],
			$url
		);
	}

	/*
	 * Initiate the workflow on a target site that the user wants to log into.
	 */
	public function receive_sso_request() : void {
		if ( empty( $_GET[ MMSSO_FROM_QUERY_VAR ] ) ) {
			return;
		} // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		if ( is_user_logged_in() ) {
			wp_redirect( remove_query_arg( [ MMSSO_FROM_QUERY_VAR, MMSSO_NONCE ] ) );
			exit();
		}

		$coming_from = (int) $_GET[ MMSSO_FROM_QUERY_VAR ]; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$sso_site    = get_site( $coming_from );

		if ( $sso_site === null ) {
			wp_die( 'Single Sign On is attempting to use an invalid site on this multisite.' );
		}

		$sso_site_url = get_site_url( $coming_from );

		// Use Mercator alias for SSO site URL if necessary.
		if ( defined( '\Mercator\VERSION' ) ) {
			// See if the target site is mapped.
			$mapping = self::get_mercator_alias( $coming_from );

			// Set SSO site URL to use the alias domain.
			if ( false !== $mapping ) {
				$sso_site_url = sprintf( '%1$s://%2$s', wp_parse_url( $sso_site_url, PHP_URL_SCHEME ), $mapping->get_domain() );
			}
		}

		if ( empty( $_GET[ MMSSO_NONCE ] ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.NonceVerification.Recommended
			wp_die( 'Single Sign On was attempted with a missing key.' );
		}

		$return_url = get_site_url() . remove_query_arg( [ MMSSO_FROM_QUERY_VAR, MMSSO_NONCE ] );
		$next_url   = add_query_arg( [
			MMSSO_RETURN_TO_QUERY_VAR => $return_url,
			MMSSO_NONCE               => sanitize_text_field( $_GET[ MMSSO_NONCE ] ), // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		], $sso_site_url );
		wp_redirect( $next_url );
		exit();
	}

	/**
	 * Used on the authorizing site
	 */
	public function authorize_request() : void {
		if ( empty( $_GET[ MMSSO_RETURN_TO_QUERY_VAR ] ) ) {
			return;
		}

		if ( ! is_user_logged_in() ) {
			wp_die( 'Single Sign On requires that you be logged in. Please <a href="' . esc_url( wp_login_url() ) . '">log in</a>, then try again.' );
		}

		$return_url = esc_url_raw( $_GET[ MMSSO_RETURN_TO_QUERY_VAR ] );

		// Prevent phishing attacks, make sure that the return-to site that gets the auth is a domain on this network.
		$url_parts          = explode( '/', $return_url );
		$requesting_site_id = get_blog_id_from_url( $url_parts[2] );
		if ( empty( $requesting_site_id ) ) {
			// Also look up if the site is using a Mercator alias.
			if ( defined( '\Mercator\VERSION' ) ) {
				// See if the target site is mapped.
				$mapping = self::get_mercator_alias( $url_parts[2] );

				// Use the correct site ID for our mapped domain.
				if ( false !== $mapping ) {
					$requesting_site_id = $mapping->get_site_id();
				}
			}

			if ( empty( $requesting_site_id ) ) {
				wp_die( 'Single Sign On failed. The requested site could not be found on this network. If someone gave you this link, they may have sent you a phishing attack.' );
			}
		}

		if ( empty( $_GET[ MMSSO_NONCE ] ) || ! wp_verify_nonce( $_GET[ MMSSO_NONCE ],
				MMSSO_NONCE_PREFIX . get_current_blog_id() . '-' . $requesting_site_id ) ) {  // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			wp_die( 'Single Sign On was attempted with a missing or bad key.' );
		}

		$current_user = wp_get_current_user();
		$expires      = strtotime( '+2 minutes' );

		/*
		 * The user's password hash is a user-specific, expire-able, private piece of information
		 * that prevents brute force hacking of the salt if an attacker has the query parameters.
		 */
		$user_pass_hash = $this->get_user_password_hash( $current_user->ID );
		if ( empty( $user_pass_hash ) ) {
			wp_die( 'Single Sign On failed. Your password hash was empty. Try changing your Wordpress password.' );
		}

		$hash = $this->hash( implode( '||', [ $current_user->ID, (int) $expires, $user_pass_hash ] ) );
		if ( empty( $hash ) ) {
			wp_die( 'Single Sign On failed. The network needs a secure salt.' );
		}

		$next_url = add_query_arg( [
			MMSSO_HASH_QUERY_VAR    => $hash,
			MMSSO_USER_ID_QUERY_VAR => $current_user->ID,
			MMSSO_EXPIRES_QUERY_VAR => $expires,
		], $return_url );
		wp_redirect( $next_url );
		exit();
	}

	/*
	 * Final step, used on the target site.
	 */
	public function receive_auth() : void {
		$keys = [ MMSSO_HASH_QUERY_VAR, MMSSO_USER_ID_QUERY_VAR, MMSSO_EXPIRES_QUERY_VAR ]; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		foreach ( $keys as $key ) {
			if ( empty( $_GET[ $key ] ) ) {
				return;
			} // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		}
		$final_destination = remove_query_arg( $keys );
		if ( is_user_logged_in() ) {
			wp_redirect( $final_destination );
			exit();
		}

		$user_id       = (int) $_GET[ MMSSO_USER_ID_QUERY_VAR ]; // phpcs:ignore:WordPress.Security.ValidatedSanitizedInput.InputNotValidated, WordPress.Security.NonceVerification.Recommended
		$expires       = (int) $_GET[ MMSSO_EXPIRES_QUERY_VAR ]; // phpcs:ignore:WordPress.Security.ValidatedSanitizedInput.InputNotValidated, WordPress.Security.NonceVerification.Recommended
		$received_hash = sanitize_text_field( $_GET[ MMSSO_HASH_QUERY_VAR ] ); // phpcs:ignore:WordPress.Security.ValidatedSanitizedInput.InputNotValidated, WordPress.Security.NonceVerification.Recommended

		if ( $expires < time() ) {
			wp_die( 'Your Single Sign On link has expired. Please return to the dashboard and try again.' );
		}
		$user_pass_hash = $this->get_user_password_hash( $user_id );
		$expected_hash  = $this->hash( implode( '||', [ $user_id, $expires, $user_pass_hash ] ) );
		if ( empty( $expected_hash ) ) {
			wp_die( 'Single Sign On failed. The network needs a secure salt.' );
		}
		if ( ! hash_equals( $expected_hash, $received_hash ) ) {
			wp_die( 'Single Sign On has found an error in the URL that you are trying to use.' );
		}
		if ( ! apply_filters( 'MMSSO_receive_auth_user_can', user_can( $user_id, 'read' ), $user_id ) ) {
			wp_die( 'Single Sign On is trying to log you in, but your user account is not authorized for this site. Please contact a network admin and ask them to add you to this site.' );

		}

		wp_set_auth_cookie( $user_id, true );

		// Just so that we don't leave the user on a URL with a bunch of our parameters.
		wp_redirect( $final_destination );
		exit();
	}

	/**
	 * @param int $uid
	 *
	 * @return string|null
	 */
	protected function get_user_password_hash( int $uid ) : ?string {
		global $wpdb;
		$hash = $wpdb->get_var( $wpdb->prepare( "SELECT user_pass FROM $wpdb->users WHERE ID = %d",
			$uid ) ); // phpcs:ignore WordPressVIPMinimum.Variables.RestrictedVariables.user_meta__wpdb__users

		return empty( $hash ) ?
			$hash :
			substr( $hash, 0, -2 ); // It's a bit safer to use only part of the password hash
	}

	/**
	 * Create a secure hash that can only be recreated from this WordPress' secret salt.
	 *
	 * @param string $thing
	 *
	 * @return false|string
	 */
	protected function hash( string $thing ) {
		if ( ! function_exists( 'hash' ) ) {
			return false;
		}
		if ( ! defined( 'AUTH_SALT' ) || empty( AUTH_SALT ) ) {
			return false;
		}

		return hash_hmac( 'sha256', $thing, AUTH_SALT );
	}

	/**
	 * Returns the first, active mapped domain object for a site ID or domain.
	 *
	 * Must be using Mercator.
	 *
	 * @param  int|string $site_id WP site ID or domain host to query for. If querying by mapped domain host,
	 *                             must not include scheme.
	 * @return \Mercator\Mapping|bool Mercator mapping object on success, boolean false on failure.
	 */
	public static function get_mercator_alias( $site_id_or_domain ) {
		if ( ! defined( '\Mercator\VERSION' ) ) {
			return false;
		}

		// See if the target site is mapped.
		if ( is_numeric( $site_id_or_domain ) ) {
			// Returns an array on success.
			$mappings = \Mercator\Mapping::get_by_site( $site_id_or_domain );
		} else {
			$mappings = \Mercator\Mapping::get_by_domain( $site_id_or_domain );

			// Returns singular, so need to set as an array.
			if ( ! empty( $mappings ) ) {
				$mappings = [
					$mappings
				];
			}
		}

		if ( ! empty( $mappings ) ) {
			// Loop through all mapped domains.
			foreach ( $mappings as $mapping ) {
				// We're only using the first, active mapped alias...
				if ( $mapping->is_active() ) {
					return $mapping;
				}
			}
		}

		return false;
	}
}

Multisite_Multidomain_Single_Sign_On::get_instance();
