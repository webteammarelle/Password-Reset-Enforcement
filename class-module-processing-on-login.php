<?php
/**
 * Enforce password reset on user login, y compris WooCommerce si actif
 *
 * @package Teydea_Studio\Password_Reset_Enforcement
 */

namespace Teydea_Studio\Password_Reset_Enforcement\Modules;

use Teydea_Studio\Password_Reset_Enforcement\Dependencies\Utils;
use Teydea_Studio\Password_Reset_Enforcement\User;
use WP_Error;
use WP_User;

final class Module_Processing_On_Login extends Utils\Module {
	/**
	 * Register hooks pour WP et, si actif, WooCommerce.
	 */
	public function register(): void {
		// WP natif
		add_filter( 'login_redirect', [ $this, 'on_wp_login_redirect' ], 10, 3 );

		// WooCommerce « My Account », seulement si WooCommerce est actif
		if ( function_exists( 'wc_get_page_permalink' ) && function_exists( 'wc_get_endpoint_url' ) ) {
			add_filter( 'woocommerce_login_redirect', [ $this, 'on_wc_login_redirect' ], 10, 2 );
		}
	}

	/**
	 * Wrapper pour le hook natif WP.
	 */
	public function on_wp_login_redirect( string $redirect_to, string $requested_redirect_to, $user ): string {
		return $this->process_login_redirect( $redirect_to, $requested_redirect_to, $user );
	}

	/**
	 * Wrapper pour le hook WooCommerce.
	 */
	public function on_wc_login_redirect( string $redirect_to, $user ): string {
		return $this->process_login_redirect( $redirect_to, '', $user );
	}

	/**
	 * Logique commune : si reset requis,
	 * on déconnecte l’utilisateur et on le renvoie
	 * vers le formulaire WooCommerce ou WP.
	 */
	protected function process_login_redirect( string $redirect_to, string $requested_redirect_to, $user ): string {
		if ( $user instanceof WP_User ) {
			$user_obj = new User( $this->container, $user );

			if ( true === $user_obj->is_password_reset_required() ) {
				// Si WooCommerce actif, on génère l'URL /lost-password/?show-reset-form=true&action
				if ( function_exists( 'wc_get_page_permalink' ) && function_exists( 'wc_get_endpoint_url' ) ) {
					$myaccount  = wc_get_page_permalink( 'myaccount' );
					$reset_base = wc_get_endpoint_url( 'lost-password', '', $myaccount );
					$reset_url  = $reset_base . '?show-reset-form=true&action';
				} else {
					// Sinon fallback WP natif
					$reset_url = $user_obj->get_password_reset_form_link();
				}

				if ( is_string( $reset_url ) ) {
					wp_logout();
					return $reset_url;
				}

				if ( is_wp_error( $reset_url ) ) {
					wp_logout();
					wp_die(
						wp_kses( $reset_url->get_error_message(), [ 'strong' => [] ] ),
						__( 'Erreur', 'teydea-password-enforcement' ),
						[ 'response' => 403 ]
					);
				}
			}
		}

		return $redirect_to;
	}
}
