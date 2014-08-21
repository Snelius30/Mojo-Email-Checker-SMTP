package Mojo::Email::Checker::SMTP;

use strict;
use Net::DNS;
use Mojo::IOLoop::Delay;
use Mojo::IOLoop::Client;
use Mojo::IOLoop::Stream;

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
			return $cb->(undef, "[ERROR] DNS resolver error: $self->{resolver}->errorstring"); 
		}
		if ($type eq 'MX') {
			push @result, $_->exchange for ($packet->answer);
			$result[0] = $domain unless (@result);
		} elsif ($type eq 'A') {
			push @result, $_->address for ($packet->answer);
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
				return $self->_connect($domains, $cb);
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
	my ($self, $err, $buffer) = @_;
	if ($err) {
		die $err;
	} elsif ($buffer && $buffer =~ /^5/) {
		die $buffer;
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
			$self->_check_errors($err, $buf);
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
			$cb->(undef, $err);
	});
}

1;
