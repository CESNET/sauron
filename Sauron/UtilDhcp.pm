# Sauron::UtilDhcp.pm - ISC DHCPD config file reading/parsing routines
#
# Copyright (c) Michal Kostenec <kostenec@civ.zcu.cz> 2013-2014.
# Copyright (c) Timo Kokkonen <tjko@iki.fi> 2002.
#
package Sauron::UtilDhcp;
require Exporter;
use IO::File;
use Sauron::Util;
use JSON;
use Data::Dumper;
use Socket qw(AF_INET AF_INET6 inet_pton);
use strict;
use vars qw(@ISA @EXPORT);

@ISA = qw(Exporter); # Inherit from Exporter
@EXPORT = qw(process_dhcpdconf process_keaconf);


my $debug = 1;

# read JSON file and included files (recursively), removing comments
sub load_json_file($) {
    my ($file_path) = @_;
   
    print "load_json_file($file_path)\n" if ($debug);
 
    # Read JSON file
    open my $fh, '<', $file_path or fatal("cannot open json file: '$file_path': $!");
    local $/;  # Umožní načíst celý soubor najednou
    my $json_text = <$fh>;
    close $fh;

    # remove comments in JSON file
    $json_text =~ s/#.*//g;      # Removes entire comment lines

    # Searching and processing include directives
    $json_text =~ s{
        <\?include\s+"([^"]+)"\?>
    }{
        my $include_path = $1;
        my $included_content = load_json_file($include_path);
        $included_content;
    }gex;

    return $json_text;    
}

# parse kea.conf file, build hash of all entries in the file
sub process_keaconf($$$) {
  my ($filename,$data,$v6)=@_;
  my ($kea_json,$kea,%state);
  my $v = $v6 ? '6' : '4';
  my $vs = $v6 ? '6' : '';

  print "process_dhcpdconf($filename,DATA)\n" if ($debug);

  $kea_json = load_json_file($filename);
  $kea_json =~ s/,\s*}/}/g;   # Resolves commas after the last element in the object
  $kea_json =~ s/,\s*]/]/g;   # Resolves commas after the last element in the array
 
#  if ($debug) { 
#    print($kea_json);
#    open my $out_fh, '>', '/tmp/keaimport.json' or fatal("cannot write json file: $!");
#    print $out_fh $kea_json;
#    close $out_fh;
#  }

  # transform JSON to Perl scalar
  my $json = JSON->new;
  $kea = eval { $json->decode($kea_json) };
  if ($@) {
      die "JSON decoding error: $@";
  }

  print Dumper($kea); 

  

  # shared-networks: -> shared-network (list of names)
  foreach my $ref_shnet (@{$$kea{"Dhcp$v"}{'shared-networks'}}) {
    push @{$$data{'shared-network'}{$$ref_shnet{name}}}, () if exists $$ref_shnet{name};

    # shared-networks:subnet -> subnet
    foreach my $ref_subnet (@{$$ref_shnet{"subnet$v"}}) {
      push @{$$data{"subnet$vs"}{$$ref_subnet{subnet}}}, "VLAN $$ref_shnet{name}" if exists $$ref_shnet{name};

      foreach my $sub_key (keys %$ref_subnet) {
        for ($sub_key) {
          /^option-data$/ and do {
	      # option-data -> group
	      foreach my $ref_opt (@{$$ref_subnet{"option-data"}}) {
		for ($$ref_opt{name}) {
		  /.*/ and do { 
                      push @{$$data{group}{"group$v-$$ref_shnet{name}-$$ref_subnet{id}"}}, "option $$ref_opt{name} $$ref_opt{data};"; 
                      last 
                    };
		}
	      }
	      last;
	    };
          /^reservations$/ and do {
	      foreach my $ref_res (@{$$ref_subnet{reservations}}) {
                 my $hostname = "";
                 if (exists($$ref_res{hostname})) {
                   $hostname = $$ref_res{hostname};
                 }
                 else {
                   my $af = $v6 ? AF_INET6 : AF_INET;
                   my $packed_ip = inet_pton($af, $$ref_res{'ip-address'});
                   $hostname = gethostbyaddr($packed_ip, $af);
		 }
                 push @{$$data{host}{"$hostname"}}, (
                            "GROUP group$v-$$ref_shnet{name}-$$ref_subnet{id}", 
                            "fixed-address $$ref_res{'ip-address'};",
                            "hardware ethernet $$ref_res{'hw-address'};"
                          );
                                                   
              }
              last ;
            };
          /^pools$/ and do {
              my $countpools = 0;
	      foreach my $ref_pools (@{$$ref_subnet{"pools"}}) {
                $countpools++;
                for (keys %{$$ref_pools}) {
                  /^pool$/ and do {
                    $$ref_pools{"pool$vs"} =~ m/^(\S+)\s*-\s*(\S+)$/;
                    push @{$$data{"pool$vs"}{"pool$vs-$$ref_subnet{id}-$countpools"}}, 
                         "range$vs $1 $2;";
                    next;
                  };
                  /.*/ and do {
                    push @{$$data{"pool$vs"}{"pool$vs-$$ref_subnet{id}-$countpools"}{$_}},
                         "$$ref_pools{$_};";
                    next;
                  };
                }


              }
              last;
            };
          /^(id|subnet)$/ and do { last; };
          /.*/ and do {
              push @{$$data{group}{"group$v-$$ref_shnet{name}-$$ref_subnet{id}"}}, "$sub_key $$ref_subnet{$sub_key};";
              last;
	    };
        } 
      }
    }

    # vsechny klice v 'subnet' je treba prejmenovat z '147.228.1.0/24' na
    # '147.228.1.0 netmask 255.255.255.0' ale jen u IPv4!
    unless ($v6) {
      foreach my $key (keys %{$$data{subnet}}) {
        # Vytvořte nový klíč s postfixem '_tst'
        my $block = Net::Netmask->new($key) or die Net::Netmask::pm_error();
    
        # Přiřaďte hodnotu starého klíče do nového
        $$data{subnet}{$block->base() . " netmask " . $block->mask()} = $$data{subnet}{$key};
    
        # Odstraňte starý klíč
        delete $$data{subnet}{$key};
      }
    } 
  }


  #TODO: pokracuj zde # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  return 0;  
}

# parse dhcpd.conf file, build hash of all entries in the file
#
sub process_dhcpdconf($$$) {
  my ($filename,$data,$v6)=@_;

  my $fh = IO::File->new();
  my ($i,$c,$tmp,$quote,$lend,$fline,$prev,%state);

  print "process_dhcpdconf($filename,DATA)\n" if ($debug);

  fatal("cannot read conf file: $filename") unless (-r $filename);
  open($fh,$filename) or fatal("cannot open conf file: $filename");

  $tmp='';
  while (<$fh>) {
    chomp;
    next if (/^\s*$/);
    next if (/^\s*#/);

    $quote=0;
    #print "line '$_'\n";
    s/\s+/\ /g; s/\s+$//; # s/^\s+//;

    for $i (0..length($_)-1) {
      $prev=($i > 0 ? substr($_,$i-1,1) : ' ');
      $c=substr($_,$i,1);
      $quote=($quote ? 0 : 1)	if (($c eq '"') && ($prev ne '\\'));
      unless ($quote) {
	last if ($c eq '#');
	$lend = ($c =~ /^[;{}]$/ ? 1 : 0);
      }
      $tmp .= $c;
      if ($lend) {
	process_line($tmp,$data,\%state,$v6);
	$tmp='';
      }
    }

    fatal("$filename($.): unterminated quoted string!\n") if ($quote);
  }
  process_line($tmp,$data,\%state,$v6);

  close($fh);

  return 0;
}

sub process_line($$$$) {
  my($line,$data,$state,$v6) = @_;

  my($tmp,$block,$rest,$ref);

  return if ($line =~ /^\s*$/);
  $line =~ s/(^\s+|\s+$)//g;
  #$line =~ s/\"//g;


  #if ($line =~ /^(\S+)\s+(\S.*)?{$/) {
  if ($line =~ /^(\S+)\s?(\s+\S.*)?{$/) {
    $block=lc($1);
    #print "BLOCK: $block\n";
    ($rest=$2) =~ s/^\s+|\s+$//g;
    $rest =~ s/\"//g;
    #print "REST: $rest\n";
    if ($block =~ /^(group)/) {
      # generate name for groups
      $$state{groupcounter}++;
      my $groupname = (!$v6 ? "group" : "group6");
      $rest="$groupname-" . $$state{groupcounter};
    }
    elsif ($block =~ /^(pool[6]?)/) {
      $$state{poolcounter}++;
      $rest="$1-" . $$state{poolcounter};
      
#warn("pools not under shared-network aren't currently supported");
    }
    #print "begin '$block:$rest'\n";
    unshift @{$$state{BLOCKS}}, $block;
    unshift @{$$state{$block}}, $rest;
    $$data{$block}->{$rest}=[] if ($rest);
    $$state{rest}=$2;

    if ($block =~ /^host/) {
      push @{$$data{$block}->{$rest}}, "GROUP $$state{group}->[0]" if ($$state{group}->[0]);
    }
    if ($block =~ /^subnet[6]?/) {
      if ($$state{'shared-network'}->[0]) {
         push @{$$data{$block}->{$rest}}, "VLAN $$state{'shared-network'}->[0]";
      }
      $$state{lastsubnet} = $rest;
    }

    return 0;
  }

  $block=$$state{BLOCKS}->[0];
  $rest=$$state{$block}->[0];

  if ($line =~ /^\s*}\s*$/) {
    #print "end '$block:$rest'\n";
    unless (@{$$state{BLOCKS}} > 0) {
      warn("mismatched parenthesis");
      return -1;
    }
    shift @{$$state{BLOCKS}};
    shift @{$$state{$block}};
    return 0;
  }

  $block='GLOBAL' unless ($block);
  #print "line($block:$rest) '$line'\n";

  if ($block eq 'GLOBAL') {
    #if($line =~ /subclass\s+\"(.*)\"\s+(.*)/) {
    if($line =~ /subclass\s+\"(.*)\"\s+(.*)/) {
        push @{$$data{'subclass'}->{$1}}, $2; 
    }
    else {
        push @{$$data{GLOBAL}}, $line;
    }
  }
  elsif ($block =~ /^(subnet[6]?|shared-network|group|class)$/) {
    push @{$$data{$block}->{$rest}}, $line;
  }
  elsif ($block =~ /^pool[6]?/) {
    push @{$$data{$block}->{$rest}}, $line;
  }
  elsif ($block =~ /^host/) {
    push @{$$data{$block}->{$rest}}, $line;
  }


  return 0;
}

1;
# eof
