package Mojo::Email::Checker::SMTP;

use strict;
use Net::DNS;
use Mojo::IOLoop::Delay;
use Mojo::IOLoop::Client;
use Mojo::IOLoop::Stream;

our $VERSION = "0.01";
use constant CRLF => "\015\012";

sub new {
	my ($class, %opts) = @_;
	bless { 
			resolver	=> Net::DNS::Resolver->new,
			reactor		=> Mojo::IOLoop->singleton->reactor,
			timeout		=> ($opts{timeout} ? $opts{timeout} : 15),
			helo		=> ($opts{helo} ? $opts{helo} : 'ya.ru')
		  }, $class;
}

sub _nslookup {
	my ($self, $domain, $type, $cb) = @_;
	my @result;
	my $sock	 = $self->{resolver}->bgsend($domain, $type);
	my $timer_id = $self->{reactor}->timer($self->{timeout} => sub {
		$self->{reactor}->remove($sock);
		$cb->(undef, '[ERROR] Timeout');
	});
	$self->{reactor}->io($sock => sub {
		$self->{reactor}->remove($timer_id);
		my $packet = $self->{resolver}->bgread($sock);
		$self->{reactor}->remove($sock);
		unless ($packet) { 
			return $cb->(undef, "[ERROR] DNS resolver error: " . $self->{resolver}->errorstring); 
		}
		if ($type eq 'MX') {
			push @result, $_->exchange for ($packet->answer);
			$result[0] = $domain unless (@result);
		} elsif ($type eq 'A') {
			push @result, $_->address for ($packet->answer);
			return $cb->(undef, "[ERROR] Can't resolve $domain") unless (@result);
		}
		$cb->(\@result);
	});
	$self->{reactor}->watch($sock, 1, 0);
}


sub _connect {
	my ($self, $domains, $cb) = @_;

	my $addr   = shift @$domains if (@$domains);
	my $client = Mojo::IOLoop::Client->new();

	$self->_nslookup($addr, 'A', sub {
		my ($ips, $err) = @_;
		
		unless ($ips) {
			if (@$domains) {
				return $self->_connect($domains, $cb);
			}
			else {
				return $cb->(undef, $err);
			}
		}
		
		$client->connect(address => $ips->[0], port => 25, timeout => $self->{timeout});
		$client->on(connect => sub {
			my $handle = pop;
			$cb->($handle);

			undef $client;
		});
		$client->on(error => sub {
			my $err = pop;

			if (@$domains) {
				$self->_connect($domains, $cb);
			} else {
				$cb->(undef, '[ERROR] Cannot connect to anything');
			}

			undef $client;
		});
	});
}

sub _readhooks {
	my ($self, $stream, $cb) = @_;

	my $buffer;
	$stream->timeout($self->{timeout});
	$stream->on(read => sub {
		my $bytes = pop;
		$buffer  .= $bytes;
		if ($bytes =~ /\n$/) {
			$stream->unsubscribe('error');
			$stream->unsubscribe('timeout');
			$stream->unsubscribe('read');
			$cb->($stream, $buffer);
		}
	});
	$stream->on(timeout => sub {
		$stream->close;
		$cb->(undef, undef, '[ERROR] Timeout');
	});
	$stream->on(error => sub {
		my $err = pop;
		$stream->close;
		$cb->(undef, undef, "[ERROR] $err");
	});

	$stream->start;
}

sub _check_errors {
	my ($self, $err, $buffer, $rcpt) = @_;
	if ($err) {
		die $err;
	} elsif ($buffer && $buffer =~ /^5/) {
		die ($rcpt ? '' : 'Reject before RCPT ') . $buffer;
	}
}

sub check {
	my ($self, $email, $cb) = @_;
	my ($domain) = $email =~  m|@(.+?)$|;

	unless ($domain) { 
		$cb->(undef, "[ERROR] Bad email address: $email");
		return; 
	}

	Mojo::IOLoop::Delay->new->steps(
		sub {
			$self->_nslookup($domain, 'MX', shift->begin(0));
		},
		sub {
			my ($delay, $addr, $err) = @_;
			$self->_check_errors($err);
			$self->_connect($addr, $delay->begin(0));
		},
		sub {
			my ($delay, $handle, $err) = @_;
			$self->_check_errors($err);
			my $stream = Mojo::IOLoop::Stream->new($handle);
			$self->_readhooks($stream, $delay->begin(0));
		},
		sub {
			my ($delay, $stream, $buf, $err) = @_;
			$self->_check_errors($err);
			$self->_readhooks($stream, $delay->begin(0));
			$stream->write("HELO $self->{helo}". CRLF);
		},
		sub {
			my ($delay, $stream, $buf, $err) = @_;
			$self->_check_errors($err, $buf);
			$self->_readhooks($stream, $delay->begin(0));
			$stream->write("MAIL FROM: <>" . CRLF);
		},
		sub {
			my ($delay, $stream, $buf, $err) = @_;
			$self->_check_errors($err, $buf);
			$self->_readhooks($stream, $delay->begin(0));
			$stream->write("RCPT TO: <$email>" . CRLF);
		},
		sub {
			my ($delay, $stream, $buf, $err) = @_;
			$self->_check_errors($err, $buf, 1);
			$self->_readhooks($stream, $delay->begin(0));
			$stream->write("QUIT" . CRLF);
		},
		sub {
			my ($delay, $stream, $buf, $err) = @_;
			$stream->close;
			$cb->($email);
		}
	)->catch(sub {
			my ($delay, $err) = @_;
			my $param = undef;
			if ($err =~ /^Reject before RCPT/) {
				$param = $email;
			}
			$cb->($param, $err);
	});
}

1;

__END__

=pod

=head1 NAME

Mojo::Email::Checker::SMTP - Email checking by smtp with Mojo enviroment.

=head1 SYNOPSIS

	use strict;
	use Mojolicious::Lite;
	use Mojo::IOLoop::Delay;
	use Mojo::Email::Checker::SMTP;

	my $checker     = Mojo::Email::Checker::SMTP->new;

	post '/' => sub {
		my $self    = shift;
		my $request = $self->req->json;

		my @emails;
		my $delay = Mojo::IOLoop::Delay->new;
		$delay->on(finish => sub {
				$self->render(json => \@emails);
		});

		my $cb = $delay->begin();

		for (@{$request}) {
			my $cb = $delay->begin(0);
			$checker->check($_, sub { push @emails, $_[0] if ($_[0]); $cb->(); });
		}

		$cb->();

	};

	app->start;

=head1 DESCRIPTION

Check for email existence by emulation smtp session to mail server (mx or direct domain, cycling for multiple ip)
and get response. Mechanism description L<http://en.wikipedia.org/wiki/Callback_verification>

=head1 METHODS

=head2 new

This is Checker object constructor. Available parameters are:

=over

=item timeout

Timeout (seconds) for all I/O operations like to connect, wait for server response and NS Lookup. (15 sec. is default).

=item helo

HELO value for smtp session ("ya.ru" :) is default). Use your own domain name for this value.

=back

=head2 check(STR, CALLBACK(EMAIL, ERROR))

Main function for checking.

=over

=item STR 

String with email address ("foo@foobox.foo")

=item CALLBACK

Reference to callback function (see SYNOPSIS for example). Pass to CALLBACK two parameters, 1. valid (see comment) EMAIL (STR), 2. ERROR (STR) message. 

B<Comment:> If EMAIL and ERROR is defined, it's mean that reject from smtp server recieved before RCPT command. In other cases only one parameter is defined.

=back

=head1 COPYRIGHT
 
 Copyright Anatoly Y. <snelius@cpan.org>.
  
  This library is free software; you can redistribute it and/or
  modify it under the same terms as Perl itself.

=cut
