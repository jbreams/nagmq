#!/usr/bin/perl

my @types = ( );
my $curtype;

while(<>) {
	s/^\s*//;
	s/\s*$//;
	s/\s+/ /g;
	/(type|flags|attr|timestamp);$/ && next;
	if(/^typedef struct (nebstruct_)?([^\s]+)_struct {/) {
		$curtype = $2;
		s/_//g;
#		print "Found struct $1\n";
		print "static json_t * parse_$curtype(nebstruct_${curtype}_data * state) {\n";
		print "\tjson_t * ret = json_object();\n\n";
		print "\tjson_object_set_new(ret, \"type\", json_string(\"${curtype}\"));\n";
		push @types, $curtype;
	}
	elsif(/^int ([^;]+);/ && $curtype) {
		print "\tjson_object_set_new(ret, \"$1\", json_integer(state->$1));\n";
	}
	elsif(/^struct timeval ([^;]+);/ && $curtype) {
		print "\tjson_object_set_new(ret, \"$1\", parse_timestamp(&state->$1));\n";
		#print "Timestamp $1\n";
	}
	elsif(/^char \*([^;]+);/ && $curtype) {
		print "\tjson_object_set_new(ret, \"$1\", json_string(state->$1));\n";
#		print "String $1\n";
	}
	elsif(/^double ([^;]+);/ && $curtype) {
		print "\tjson_object_set_new(ret, \"$1\", json_real(state->$1));\n";
#		print "Double $1\n";
	}
	elsif(/^unsigned long ([^;]+);/ && $curtype) {
		print "\tjson_object_set_new(ret, \"$1\", json_integer(state->$1));\n";
	}
	elsif(/^time_t ([^;]+);/ && $curtype) {
		print "\tjson_object_set_new(ret, \"$1\", json_integer(state->$1));\n";
	#	print "Time_t $1\n"
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
