<?php
/*
Plugin Name: Anti spam
Plugin URI: http://yourls.org/
Description: Checks URL against DNS blacklists. Might OR MIGHT NOT work for you. Read the readme.
Version: 1.1
Author: Ozh
Author URI: http://ozh.org/
*/


// Check for spam when someone adds a new link
yourls_add_filter( 'shunt_add_new_link', 'ozh_yourls_antispam_check_add' );
function ozh_yourls_antispam_check_add( $false, $url ) {
    // Sanitize URL and make sure there's a protocol
    $url = yourls_sanitize_url( $url );

    // only check for 'http(s)'
    if( !in_array( yourls_get_protocol( $url ), array( 'http://', 'https://' ) ) )
        return $false;

    if ( ozh_yourls_antispam_is_blacklisted( $url ) === yourls_apply_filter( 'ozh_yourls_antispam_malformed', 'malformed' ) ) {
		return array(
			'status' => 'fail',
			'code'   => 'error:nourl',
			'message' => yourls__( 'Missing or malformed URL' ),
			'errorCode' => '400',
		);
    }

    if ( ozh_yourls_antispam_is_blacklisted( $url ) != false ) {
		return array(
			'status' => 'fail',
			'code'   => 'error:spam',
			'message' => 'This domain is blacklisted',
			'errorCode' => '403',
		);
    }

	// All clear, not interrupting the normal flow of events
	return $false;
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
			// Delete link & die. Return false from this filter to only block the redirect and keep the link.
			if( yourls_apply_filter( 'ozh_yourls_antispam_delete_on_redirect', true, $keyword, $url ) ) {
				yourls_delete_link_by_keyword( $keyword );
				yourls_die( 'This domain has been blacklisted. This short URL has been deleted from our record.', 'Domain blacklisted', '403' );
			}
			yourls_die( 'This domain has been blacklisted.', 'Domain blacklisted', '403' );
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
            'bl.spamcop.net',
		)
	);

	// Check against each blacklist, exit if blacklisted
	foreach( $blacklists as $blacklist ) {
		// Skip lists that are dead or list everything, so they can't flag (and delete) every link
		if( !ozh_yourls_antispam_list_is_sane( $blacklist ) )
			continue;

		if( ozh_yourls_antispam_dns_listed( $parsed['host'] . '.' . $blacklist . '.' ) )
			return yourls_apply_filter( 'ozh_yourls_antispam_blacklisted', true );
	}

	// All clear, probably not spam
	return yourls_apply_filter( 'ozh_yourls_antispam_clean', false );
}


// Does this DNSBL name have a "listed" answer? Only an A record in 127.0.0.0/8 counts.
// Any other record (eg a wildcard TXT on a defunct list, or the HINFO "RFC8482" stub some resolvers return to ANY
// queries) is not a listing, and neither are the "query refused" codes: 127.0.0.1 (SURBL, URIBL) and
// 127.255.255.0/24 (Spamhaus: public resolver, rate limit, bad query).
function ozh_yourls_antispam_dns_listed( $name ) {
	$records = @dns_get_record( $name, DNS_A );
	if( !$records )
		return false;

	foreach( $records as $record ) {
		$ip = isset( $record['ip'] ) ? $record['ip'] : '';
		if( strpos( $ip, '127.' ) !== 0 || $ip == '127.0.0.1' || strpos( $ip, '127.255.255.' ) === 0 )
			continue;
		return true;
	}

	return false;
}


// Is this list answering sanely? RFC 5782 says a DNSBL must never list "invalid", so a list that does is
// broken (shut down lists sometimes start listing the whole world) and must be ignored. Checked once per request.
function ozh_yourls_antispam_list_is_sane( $blacklist ) {
	static $sane = array();

	if( !isset( $sane[ $blacklist ] ) ) {
		$sane[ $blacklist ] = !ozh_yourls_antispam_dns_listed( 'invalid.' . $blacklist . '.' );
		if( !$sane[ $blacklist ] && function_exists( 'yourls_debug_log' ) )
			yourls_debug_log( "Antispam: $blacklist lists everything (even 'invalid'), skipping it" );
	}

	return $sane[ $blacklist ];
}
