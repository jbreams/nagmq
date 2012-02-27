#!/usr/bin/perl

my @types = ( );
my $curtype;

while(<>) {
	s/^\s*//;
	s/\s*$//;
	s/\s+/ /g;
	/(type|flags|attr|timestamp);$/ && next;
	if(/^(typedef )?struct (nebstruct_)?([^\s]+)_struct {/) {
		$curtype = $3;
		s/_//g;
		print "Found struct $curtype\n";
		print "static struct payload * parse_$curtype(nebstruct_${curtype}_data * state) {\n";
		print "\tstruct payload * ret = payload_new();\n\n";
		print "\tpaload_new_string(ret, \"type\", \"${curtype}\");\n";
		push @types, $curtype;
	}
	elsif(/^(?:int|unsigned long|time_t) ([^;]+);/ && $curtype) {
		print "\tpayload_new_integer(ret, \"$1\", state->$1);\n";
	}
	elsif(/^double ([^;]+);/ && $curtype) {
		print "\tpayload_new_double(ret, \"$1\", state->$1);\n";
	}
	elsif(/^struct timeval ([^;]+);/ && $curtype) {
		print "\tparse_timestamp(ret, \"$1\", &state->$1);\n";
		#print "Timestamp $1\n";
	}
	elsif(/^char \*([^;]+);/ && $curtype) {
		print "\tpayload_new_string(ret, \"$1\", state->$1);\n";
#		print "String $1\n";
	}
	elsif(/^}/) {
		$curtype && print "\treturn ret;\n}\n\n";
		undef $curtype;
	}
}

foreach (@types) {
	s/_data$//;
	print "\tcase NEBCALLBACK_" . uc $_ . "_DATA:\n";
	print "\t\tpaylod = parse_$_(obj);\n";
	print "\t\tbreak;\n";
}
