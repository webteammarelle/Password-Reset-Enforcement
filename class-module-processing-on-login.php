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
	 * Register hooks pour WP natif et, si actif, WooCommerce.
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
	 * vers le formulaire de saisie du nouveau mot de passe.
	 *
	 * @param string           $redirect_to           URL de redirection par défaut.
	 * @param string           $requested_redirect_to URL demandée (ou '').
	 * @param WP_User|WP_Error $user                  Objet WP_User ou WP_Error.
	 * @return string URL finale de redirection.
	 */
	protected function process_login_redirect( string $redirect_to, string $requested_redirect_to, $user ): string {
		// On ne touche qu'aux connexions réussies
		if ( $user instanceof WP_User ) {
			$wp_user  = $user; // instance native
			$user_obj = new User( $this->container, $wp_user );

			if ( true === $user_obj->is_password_reset_required() ) {
				// Génère la clé sans email
				$key = get_password_reset_key( $wp_user );
				if ( is_wp_error( $key ) ) {
					// Impossible de générer la clé : on affiche l'erreur
					wp_logout();
					wp_die(
						wp_kses( $key->get_error_message(), [ 'strong' => [] ] ),
						__( 'Erreur', 'teydea-password-enforcement' ),
						[ 'response' => 500 ]
					);
				}

				// Si WooCommerce actif, on pointe vers le formulaire de reset
				if ( function_exists( 'wc_get_page_permalink' ) && function_exists( 'wc_get_endpoint_url' ) ) {
					$myaccount_url = wc_get_page_permalink( 'myaccount' );
					// URL de base : /my-account/lost-password/
					$base = wc_get_endpoint_url( 'lost-password', '', $myaccount_url );
					// Ajout des paramètres 'key' et 'login'
					$reset_url = add_query_arg(
						[
							'key'   => $key,
							'login' => rawurlencode( $wp_user->user_login ),
						],
						$base
					);
				} else {
					// Fallback WP natif
					$reset_url = $user_obj->get_password_reset_form_link();
				}

				// Déconnexion et redirection
				if ( is_string( $reset_url ) ) {
					wp_logout();
					return $reset_url;
				}

				// En cas d'erreur WP_Error
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

