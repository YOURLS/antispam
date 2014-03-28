<?php
/*
Plugin Name: Anti spam
Plugin URI: http://yourls.org/
Description: Absolute anti-spam plugin. Checks URL against major black lists and removes all crap.
Version: 1.0.2
Author: Ozh
Author URI: http://ozh.org/
*/


// Check for spam when someone adds a new link
yourls_add_filter( 'shunt_add_new_link', 'ozh_yourls_antispam_check_add' );
function ozh_yourls_antispam_check_add( $false, $url ) {
	if ( ozh_yourls_antispam_is_blacklisted( $url ) != false ) {
		return array(
			'status' => 'fail',
			'code'   => 'error:spam',
			'message' => 'This domain is blacklisted',
			'errorCode' => '403',
		);
	}
	
	// All clear, not interrupting the normal flow of events
	return false;
}


// Has the remote link become compromised lately? Check on redirection
yourls_add_action( 'redirect_shorturl', 'ozh_yourls_antispam_check_redirect' );
function ozh_yourls_antispam_check_redirect( $url, $keyword = false ) {
	
	if( is_array( $url ) && $keyword == false ) {
		$keyword = $url[1];
		$url = $url[0];
	}
	
	// Check when the link was added
	// If shorturl is fresh (ie probably clicked more often?) check once every 15 times, otherwise once every 5 times
	// Define fresh = 3 days = 259200 secondes
	// TODO: when there's a shorturl_meta table, store last check date to allow checking every 2 or 3 days
	$now  = date( 'U' );
	$then = date( 'U', strtotime( yourls_get_keyword_timestamp( $keyword ) ) );
	$chances = ( ( $now - $then ) > 259200 ? 15 : 5 );
	
	if( $chances == mt_rand( 1, $chances ) ) {
		if( ozh_yourls_antispam_is_blacklisted( $url ) != false ) {
			// Delete link & die
			yourls_delete_link_by_keyword( $keyword );
			yourls_die( 'This domain has been blacklisted. This short URL has been deleted from our record.', 'Domain blacklisted', '403' );
		}
	}

	// Nothing, move along

}


// Is the link spam? true for "yes it's shit", false for "nope, safe"
function ozh_yourls_antispam_is_blacklisted( $url ) {
	$parsed = parse_url( $url );
	
	if( !isset( $parsed['host'] ) )
		return yourls_apply_filter( 'ozh_yourls_antispam_malformed', 'malformed' );
	
	// Remove www. from domain (but not from www.com)
	$parsed['host'] = preg_replace( '/^www\.(.+\.)/i', '$1', $parsed['host'] );
	
	// Major blacklists. There's a filter if you want to manipulate this.
	$blacklists = yourls_apply_filter( 'ozh_yourls_antispam_list',
		array(
			'zen.spamhaus.org',
			'multi.surbl.org',
			'black.uribl.com',
		)
	);
	
	// Check against each blacklist, exit if blacklisted
	foreach( $blacklists as $blacklist ) {
		$domain = $parsed['host'] . '.' . $blacklist . '.';
		$record = @dns_get_record( $domain );
		
		if( $record && count( $record ) > 0 )
			return yourls_apply_filter( 'ozh_yourls_antispam_blacklisted', true );
	}
	
	// All clear, probably not spam
	return yourls_apply_filter( 'ozh_yourls_antispam_clean', false );
}
