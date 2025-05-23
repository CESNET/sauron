# Sauron::CGI::Templates.pm
#
# Copyright (c) Timo Kokkonen <tjko@iki.fi>  2003.
#
package Sauron::CGI::Templates;
require Exporter;
use CGI qw/:standard *table -no_xhtml/;
use Sauron::DB;
use Sauron::CGIutil;
use Sauron::BackEnd;
use Sauron::Sauron;
use Sauron::CGI::Utils;
use strict;
use vars qw(@ISA @EXPORT);

@ISA = qw(Exporter); # Inherit from Exporter
@EXPORT = qw(
	    );



my %mx_template_form=(
 data=>[
  {ftype=>0, name=>'MX template'},
  {ftype=>1, tag=>'name', name=>'Name', type=>'text',len=>40, empty=>0},
  {ftype=>4, tag=>'id', name=>'ID'},
  {ftype=>1, tag=>'alevel', name=>'Authorization level', type=>'priority', 
   len=>3, empty=>0},
  {ftype=>1, tag=>'comment', name=>'Comment', type=>'text',len=>60, empty=>1},
  {ftype=>2, tag=>'mx_l', name=>'Mail exchanges (MX)',
   type=>['priority','mx','text'], fields=>3, len=>[5,50,20],
   empty=>[0,0,1],elabels=>['Priority','MX','comment']},
  {ftype=>0, name=>'Record info', no_edit=>1},
  {ftype=>4, name=>'Record created', tag=>'cdate_str', no_edit=>1},
  {ftype=>4, name=>'Last modified', tag=>'mdate_str', no_edit=>1}
 ]
);

my %wks_template_form=(
 data=>[
  {ftype=>0, name=>'WKS template'},
  {ftype=>1, tag=>'name', name=>'Name', type=>'text',len=>40, empty=>0},
  {ftype=>4, tag=>'id', name=>'ID'},
  {ftype=>1, tag=>'alevel', name=>'Authorization level', type=>'priority', 
   len=>3, empty=>0},
  {ftype=>1, tag=>'comment', name=>'Comment', type=>'text',len=>60, empty=>1},
  {ftype=>2, tag=>'wks_l', name=>'WKS', 
   type=>['text','text','text'], fields=>3, len=>[10,30,10], empty=>[0,1,1], 
   elabels=>['Protocol','Services','comment']},
  {ftype=>0, name=>'Record info', no_edit=>1},
  {ftype=>4, name=>'Record created', tag=>'cdate_str', no_edit=>1},
  {ftype=>4, name=>'Last modified', tag=>'mdate_str', no_edit=>1}
 ]
);

my %printer_class_form=(
 data=>[
  {ftype=>0, name=>'PRINTER class'},
  {ftype=>1, tag=>'name', name=>'Name', type=>'printer_class',len=>20,
   empty=>0},
  {ftype=>4, tag=>'id', name=>'ID'},
  {ftype=>1, tag=>'comment', name=>'Comment', type=>'text',len=>60, empty=>1},
  {ftype=>2, tag=>'printer_l', name=>'PRINTER', 
   type=>['text','text'], fields=>2, len=>[60,10], empty=>[0,1],
   elabels=>['Printer','comment']},
  {ftype=>0, name=>'Record info', no_edit=>1},
  {ftype=>4, name=>'Record created', tag=>'cdate_str', no_edit=>1},
  {ftype=>4, name=>'Last modified', tag=>'mdate_str', no_edit=>1}
 ]
);

my %hinfo_template_form=(
 data=>[
  {ftype=>0, name=>'HINFO template'},
  {ftype=>1, tag=>'hinfo', name=>'HINFO', type=>'hinfo',len=>20, empty=>0},
  {ftype=>4, tag=>'id', name=>'ID', iff=>['id','\d+']},
  {ftype=>3, tag=>'type', name=>'Type', type=>'enum',
   enum=>{0=>'Hardware',1=>'Software'}},
  {ftype=>1, tag=>'pri', name=>'Priority', type=>'priority',len=>4, empty=>0},
  {ftype=>0, name=>'Record info', no_edit=>1},
  {ftype=>4, name=>'Record created', tag=>'cdate_str', no_edit=>1},
  {ftype=>4, name=>'Last modified', tag=>'mdate_str', no_edit=>1}
 ]
);



sub restricted_add_mx_template($) {
  my($rec)=@_;

  if (check_perms('tmplmask',$rec->{name},1)) {
    alert1("Invalid template name: not authorized to create");
    return -101;
  }
  return add_mx_template($rec);
}

sub restricted_update_mx_template($) {
  my($rec)=@_;

  if (check_perms('tmplmask',$rec->{name},1)) {
    alert1("Invalid template name: not authorized to update");
    return -101;
  }
  return update_mx_template($rec);
}

sub restricted_get_mx_template($$) {
  my($id,$rec)=@_;

  my($r);
  $r=get_mx_template($id,$rec);
  return $r if ($r < 0);

  if (check_perms('tmplmask',$rec->{name},1)) {
    alert1("Invalid template name: not authorized to modify");
    return -101;
  }
  return $r;
}



# TEMPLATES menu
#
sub menu_handler {
  my($state,$perms) = @_;

  my(@q,$i,$id,$res,$new_id);
  my(%data,%lsth,@lst,%mxhash,%wkshash,%pchash,%hinfohash,%h);

  my $serverid = $state->{serverid};
  my $server = $state->{server};
  my $zoneid = $state->{zoneid};
  my $zone = $state->{zone};
  my $selfurl = $state->{selfurl};

  unless ($serverid > 0) {
    print h2("Server not selected!");
    return;
  }
  unless ($zoneid > 0) {
    print h2("Zone not selected!");
    return;
  }
  return if (check_perms('server','R'));

  my $sub=param('sub');
  my $mx_id=param('mx_id');
  my $wks_id=param('wks_id');
  my $pc_id=param('pc_id');
  my $hinfo_id=param('hinfo_id');

  if ($sub eq 'mx') {
  show_mx_template_list:
    db_query("SELECT name,comment,alevel,id FROM mx_templates " .
	     "WHERE zone=$zoneid ORDER BY name;",\@q);
    print h3("MX templates for zone: $zone");
    for $i (0..$#q) {
	$q[$i][0]=
	  "<a href=\"$selfurl?menu=templates&mx_id=$q[$i][3]\">$q[$i][0]</a>";
    }
    display_list(['Name','Comment','Lvl'],\@q,0);
    print "<br>";
    return;
  }
  elsif ($sub eq 'wks') {
    db_query("SELECT name,comment,alevel,id FROM wks_templates " .
	     "WHERE server=$serverid ORDER BY name;",\@q);
    print h3("WKS templates for server: $server");

    for $i (0..$#q) {
      $q[$i][0]=
	"<a href=\"$selfurl?menu=templates&wks_id=$q[$i][3]\">$q[$i][0]</a>";
    }
    display_list(['Name','Comment','Lvl'],\@q,0);
    print "<br>";
    return;
  }
  elsif ($sub eq 'pc') {
    db_query("SELECT id,name,comment FROM printer_classes " .
	     "ORDER BY name;",\@q);
    print h3("PRINTER Classes (global)");

    for $i (0..$#q) {
      $q[$i][1]=
	"<a href=\"$selfurl?menu=templates&pc_id=$q[$i][0]\">$q[$i][1]</a>";
    }
    display_list(['Name','Comment'],\@q,1);
    print "<br>";
    return;
  }
  elsif ($sub eq 'hinfo') {
    db_query("SELECT id,type,hinfo,pri FROM hinfo_templates " .
	     "ORDER BY type,pri,hinfo;",\@q);

    print h3("HINFO templates (global)");

    for $i (0..$#q) {
	$q[$i][1]=($q[$i][1]==0 ? "Hardware" : "Software");
	$q[$i][2]="<a href=\"$selfurl?menu=templates&hinfo_id=$q[$i][0]\">" .
	          "$q[$i][2]</a>";
    }
    display_list(['Type','HINFO','Priority'],\@q,1);
    print "<br>";
    return;
  }
  elsif ($sub eq 'Edit') {
    if ($mx_id > 0) {
      $res=edit_magic('mx','MX template','templates',\%mx_template_form,
		      \&restricted_get_mx_template,
		      \&restricted_update_mx_template,$mx_id);
      goto show_mxt_record if ($res > 0);
    } elsif ($wks_id > 0) {
      return if (check_perms('superuser',''));
      $res=edit_magic('wks','WKS template','templates',\%wks_template_form,
		      \&get_wks_template,\&update_wks_template,$wks_id);
      goto show_wkst_record if ($res > 0);
    } elsif ($pc_id > 0) {
      return if (check_perms('superuser',''));
      $res=edit_magic('pc','PRINTER class','templates',\%printer_class_form,
		      \&get_printer_class,\&update_printer_class,$pc_id);
      goto show_pc_record if ($res > 0);
    } elsif ($hinfo_id > 0) {
      return if (check_perms('superuser',''));
      $res=edit_magic('hinfo','HINFO template','templates',
		      \%hinfo_template_form,
		      \&get_hinfo_template,\&update_hinfo_template,$hinfo_id);
      goto show_hinfo_record if ($res > 0);
    } else { print p,"Unknown template type!"; }
    return;
  }
  elsif ($sub eq 'Delete') {
    if ($mx_id > 0) {
      if (get_mx_template($mx_id,\%h)) {
	print h2("Cannot get mx template (id=$mx_id)");
	return;
      }
      return if (check_perms('tmplmask',$h{name}));
      if (param('mx_cancel')) {
	print h2('MX template not removed');
	goto show_mxt_record;
      }
      elsif (param('mx_confirm')) {
	$new_id=param('mx_new');
	if ($new_id eq $mx_id) {
	  print h2("Cannot change host records to point template " .
		   "being deleted!");
	  goto show_mxt_record;
	}
	$new_id=-1 unless ($new_id > 0);
	if (db_exec("UPDATE hosts SET mx=$new_id WHERE mx=$mx_id;") < 0) {
	  print h2('Cannot update records pointing to this template!');
	  return;
	}
	if (delete_mx_template($mx_id) < 0) {
	  print "<FONT color=\"red\">",h1("MX template delete failed!"),
	        "</FONT>";
	  return;
	}
	print h2("MX template successfully deleted.");
	return;
      }

      undef @q;
      db_query("SELECT COUNT(id) FROM hosts WHERE mx=$mx_id;",\@q);
      print p,"$q[0][0] host records use this template.",
	      start_form(-method=>'GET',-action=>$selfurl);
      if ($q[0][0] > 0) {
	get_mx_template_list($zoneid,\%lsth,\@lst,$perms->{alevel});
	print p,"Change those host records to point to: ",
	        popup_menu(-name=>'mx_new',-values=>\@lst,
			   -default=>-1,-labels=>\%lsth);
      }
      print hidden('menu','templates'),hidden('sub','Delete'),
	      hidden('mx_id',$mx_id),p,
	      submit(-name=>'mx_confirm',-value=>'Delete'),"  ",
	      submit(-name=>'mx_cancel',-value=>'Cancel'),end_form;
      display_form(\%h,\%mx_template_form);

    } elsif ($wks_id > 0) {
      return if (check_perms('superuser',''));
      if (get_wks_template($wks_id,\%h)) {
	print h2("Cannot get wks template (id=$wks_id)");
	return;
      }
      if (param('wks_cancel')) {
	print h2('WKS template not removed');
	goto show_wkst_record;
      } 
      elsif (param('wks_confirm')) {
	$new_id=param('wks_new');
	if ($new_id eq $wks_id) {
	  print h2("Cannot change host records to point template " .
		   "being deleted!");
	  goto show_wkst_record;
	}
	$new_id=-1 unless ($new_id > 0);
	if (db_exec("UPDATE hosts SET wks=$new_id WHERE wks=$wks_id;") < 0) {
	  print h2('Cannot update records pointing to this template!');
	  return;
	}
	if (delete_wks_template($wks_id) < 0) {
	  print "<FONT color=\"red\">",h1("WKS template delete failed!"),
	        "</FONT>";
	  return;
	}
	print h2("WKS template successfully deleted.");
	return;
      }

      undef @q;
      db_query("SELECT COUNT(id) FROM hosts WHERE wks=$wks_id;",\@q);
      print p,"$q[0][0] host records use this template.",
	      start_form(-method=>'GET',-action=>$selfurl);
      if ($q[0][0] > 0) {
	get_wks_template_list($serverid,\%lsth,\@lst,$perms->{alevel});
	print p,"Change those host records to point to: ",
	        popup_menu(-name=>'wks_new',-values=>\@lst,
			   -default=>-1,-labels=>\%lsth);
      }
      print hidden('menu','templates'),hidden('sub','Delete'),
	      hidden('wks_id',$wks_id),p,
	      submit(-name=>'wks_confirm',-value=>'Delete'),"  ",
	      submit(-name=>'wks_cancel',-value=>'Cancel'),end_form;
      display_form(\%h,\%wks_template_form);

    }
    elsif ($pc_id > 0) {
      return if (check_perms('superuser',''));
      $res=delete_magic('pc','PRINTER class','templates',\%printer_class_form,
			\&get_printer_class,\&delete_printer_class,$pc_id);
      goto show_pc_record if ($res==2);
    }
    elsif ($hinfo_id > 0) {
      return if (check_perms('superuser',''));
      $res=delete_magic('hinfo','HINFO template','templates',
			\%hinfo_template_form,\&get_hinfo_template,
			\&delete_hinfo_template,$hinfo_id);
      goto show_hinfo_record if ($res==2);
    }
    else { print p,"Unknown template type!"; }
    return;
  }
  elsif ($sub eq 'addmx') {
    $data{zone}=$zoneid; $data{alevel}=0; $data{mx_l}=[];
    $res=add_magic('addmx','MX template','templates',\%mx_template_form,
		   \&restricted_add_mx_template,\%data);
    if ($res > 0) {
      $mx_id=$res;
      goto show_mxt_record;
    }
    return;
  }
  elsif ($sub eq 'addwks') {
    return if (check_perms('superuser',''));
    $data{server}=$serverid; $data{alevel}=0; $data{wks_l}=[];
    $res=add_magic('addwks','WKS template','templates',\%wks_template_form,
		   \&add_wks_template,\%data);
    if ($res > 0) {
      $wks_id=$res;
      goto show_wkst_record;
    }
    return;
  }
  elsif ($sub eq 'addpc') {
    return if (check_perms('superuser',''));
    $data{printer_l}=[];
    $res=add_magic('addwpc','PRINTER class','templates',
		   \%printer_class_form,\&add_printer_class,\%data);
    if ($res > 0) {
      $pc_id=$res;
      goto show_pc_record;
    }
    return;
  }
  elsif ($sub eq 'addhinfo') {
    return if (check_perms('superuser',''));
    $data{type}=0;
    $data{pri}=100;
    $res=add_magic('addhinfo','HINFO template','templates',
		   \%hinfo_template_form,\&add_hinfo_template,\%data);
    if ($res > 0) {
      $hinfo_id=$res;
      goto show_hinfo_record;
    }
    return;
  }
  elsif ($mx_id > 0) {
  show_mxt_record:
    if (get_mx_template($mx_id,\%mxhash)) {
      print h2("Cannot get MX template (id=$mx_id)!");
      return;
    }
    display_form(\%mxhash,\%mx_template_form);
    print p,start_form(-method=>'GET',-action=>$selfurl),
          hidden('menu','templates');
    print submit(-name=>'sub',-value=>'Edit'), "  ",
          submit(-name=>'sub',-value=>'Delete')
	    unless (check_perms('tmplmask',$mxhash{name},1));
    print hidden('mx_id',$mx_id),end_form;
    return;
  }
  elsif ($wks_id > 0) {
  show_wkst_record:
    if (get_wks_template($wks_id,\%wkshash)) {
      print h2("Cannot get WKS template (id=$wks_id)!");
      return;
    }
    display_form(\%wkshash,\%wks_template_form);
    print p,start_form(-method=>'GET',-action=>$selfurl),
          hidden('menu','templates');
    print submit(-name=>'sub',-value=>'Edit'), "  ",
          submit(-name=>'sub',-value=>'Delete')
	    unless (check_perms('superuser','',1));
    print hidden('wks_id',$wks_id),end_form;
    return;
  }
  elsif ($pc_id > 0) {
  show_pc_record:
    if (get_printer_class($pc_id,\%pchash)) {
      print h2("Cannot get PRINTER class (id=$pc_id)!");
      return;
    }
    display_form(\%pchash,\%printer_class_form);
    print p,start_form(-method=>'GET',-action=>$selfurl),
          hidden('menu','templates');
    print submit(-name=>'sub',-value=>'Edit'), "  ",
          submit(-name=>'sub',-value=>'Delete')
	    unless (check_perms('superuser','',1));
    print hidden('pc_id',$pc_id),end_form;
    return;
  }
  elsif ($hinfo_id > 0) {
  show_hinfo_record:
    if (get_hinfo_template($hinfo_id,\%hinfohash)) {
      print h2("Cannot get HINFO template (id=$hinfo_id)!");
      return;
    }
    display_form(\%hinfohash,\%hinfo_template_form);
    print p,start_form(-method=>'GET',-action=>$selfurl),
          hidden('menu','templates');
    print submit(-name=>'sub',-value=>'Edit'), "  ",
          submit(-name=>'sub',-value=>'Delete')
	    unless (check_perms('superuser','',1));
    print hidden('hinfo_id',$hinfo_id),end_form;
    return;
  }

  # display MX template list by default
  goto show_mx_template_list;
}




1;
# eof
