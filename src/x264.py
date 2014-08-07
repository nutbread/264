#!/usr/bin/env python
import os, re, sys, json, time, subprocess;
version_info = [ 1 , 0 ];



# Python 2/3 support
if (sys.version_info[0] == 3):
	# Version 3
	def py_2or3_str_to_bytes(text, encoding="ascii", errors="strict"):
		return bytes(text, encoding, errors);
	def py_2or3_bytes_to_str(text, encoding="ascii", errors="strict"):
		return text.decode(encoding, errors);
	def py_2or3_byte_ord(char):
		return char;
else:
	# Version 2
	def py_2or3_str_to_bytes(text, encoding="ascii", errors="strict"):
		return text.encode(encoding, errors);
	def py_2or3_bytes_to_str(text, encoding="ascii", errors="strict"):
		return text.decode(encoding, errors);
	def py_2or3_byte_ord(char):
		return ord(char);



# Exceptions
class ExeNotFoundError(Exception):
	pass;



# Argument parser
def arguments_parse(arguments, start, descriptor, flagless_argument_order=[], stop_after_all_flagless=False, return_level=0):
	# Setup data
	argument_values = {};
	argument_aliases_short = {};
	argument_aliases_long = {};
	errors = [];

	for k,v in descriptor.items():
		if ("bool" in v and v["bool"] == True):
			argument_values[k] = False;
		else:
			argument_values[k] = None;

		if ("short" in v):
			for flag in v["short"]:
				argument_aliases_short[flag] = k;

		if ("long" in v):
			for flag in v["long"]:
				argument_aliases_long[flag] = k;

	# Parse command line
	end = len(arguments);
	while (start < end):
		# Check
		arg = arguments[start];
		if (len(arg) > 0 and arg[0] == "-"):
			if (len(arg) == 1):
				# Single "-"
				errors.append("Invalid argument {0:s}".format(repr(arg)));
			else:
				if (arg[1] == "-"):
					# Long argument
					arg = arg[2 : ];
					if (arg in argument_aliases_long):
						# Set
						arg_key = argument_aliases_long[arg];
						if (argument_values[arg_key] == False or argument_values[arg_key] == True):
							# No value
							argument_values[arg_key] = True;
						else:
							if (start + 1 < end):
								# Value
								start += 1;
								argument_values[arg_key] = arguments[start];
							else:
								# Invalid
								errors.append("No value specified for flag {0:s}".format(repr(arg)));

						# Remove from flagless_argument_order
						if (arg_key in flagless_argument_order):
							flagless_argument_order.pop(flagless_argument_order.index(arg_key));
					else:
						# Invalid
						errors.append("Invalid long flag {0:s}".format(repr(arg)));

				else:
					# Short argument(s)
					arg = arg[1 : ];
					arg_len = len(arg);
					i = 0;
					while (i < arg_len):
						if (arg[i] in argument_aliases_short):
							# Set
							arg_key = argument_aliases_short[arg[i]];
							if (argument_values[arg_key] == False or argument_values[arg_key] == True):
								# No value
								argument_values[arg_key] = True;
							else:
								if (i + 1 < arg_len):
									# Trailing value
									argument_values[arg_key] = arg[i + 1 : ];
									i = arg_len; # Terminate
								elif (start + 1 < end):
									# Value
									start += 1;
									argument_values[arg_key] = arguments[start];
								else:
									# Invalid
									errors.append("No value specified for flag {0:s}".format(repr(arg)));

							# Remove from flagless_argument_order
							if (arg_key in flagless_argument_order):
								flagless_argument_order.pop(flagless_argument_order.index(arg_key));
						else:
							# Invalid
							in_str = "";
							if (arg[i] != arg): in_str = " in {0:s}".format(repr(arg));
							errors.append("Invalid short flag {0:s}{1:s}".format(repr(arg[i]), in_str));

						# Next
						i += 1;

		elif (len(flagless_argument_order) > 0):
			# Set
			arg_key = flagless_argument_order[0];
			if (argument_values[arg_key] == False or argument_values[arg_key] == True):
				# No value
				argument_values[arg_key] = True;
			else:
				# Value
				argument_values[arg_key] = arg;

			# Remove from flagless_argument_order
			flagless_argument_order.pop(0);
		else:
			# Invalid
			errors.append("Invalid argument {0:s}".format(repr(arg)));

		# Next
		start += 1;
		if (stop_after_all_flagless and len(flagless_argument_order) == 0): break; # The rest are ignored


	# Return
	if (return_level <= 0):
		return argument_values;
	else:
		return ( argument_values , errors , flagless_argument_order , start )[0 : return_level + 1];

# Convert a list of arguments into a string of arguments which can be executed on the command line
def argument_list_to_command_line_string(arguments, forced):
	args_new = [];
	re_valid_pattern = re.compile(r"^[a-zA-Z0-9_\-\.\+\:\\/]+$");
	for arg in arguments:
		# Format the argument
		if (forced or re_valid_pattern.match(arg) is None):
			arg = '"{0:s}"'.format(arg.replace('"', '""'));

		# Add
		args_new.append(arg);

	# Join and return
	return " ".join(args_new);



# Get file info
def ffinfo(in_filename, ffprobe_exe="ffprobe"):
	# Setup process
	try:
		cmd = [
			ffprobe_exe,
			"-v", "quiet",
			"-print_format", "json",
			"-show_format",
			"-show_streams",
			"-i", in_filename
		];
		p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE);
	except OSError:
		# No file
		raise ExeNotFoundError("The executable file {0:s} was not found".format(repr(ffprobe_exe)));

	# Communicate
	p_stdout = p.communicate()[0];

	# Decode unicode
	try:
		p_stdout = p_stdout.decode("utf-8");
	except UnicodeDecodeError:
		pass;

	# Decode json
	try:
		info = json.loads(p_stdout);

		# Must be a dict
		if (not isinstance(info, dict)): info = {};
	except ValueError:
		# Invalid json
		info = {};

	# Done
	return info;

# Usage info
def usage(arguments_descriptor, stream):
	usage_info = [
		"Usage:",
		"    {0:s} [<script-arguments> @] <x264-arguments> input-filename".format(os.path.split(sys.argv[0])[1]),
		"\n",
		"Available flags:",
	];

	# Flags
	argument_keys = sorted(arguments_descriptor.keys());

	for i in range(len(argument_keys)):
		key = argument_keys[i];
		arg = arguments_descriptor[key];
		param_name = "";
		if (not ("bool" in arg and arg["bool"])):
			if ("argument" in arg):
				param_name = " <{0:s}>".format(arg["argument"]);
			else:
				param_name = " <value>";

		if (i > 0):
			usage_info.append("");

		if ("long" in arg):
			for a in arg["long"]:
				usage_info.append("  --{0:s}{1:s}".format(a, param_name));

		if ("short" in arg):
			usage_info.append("  {0:s}".format(", ".join([ "-{0:s}{1:s}".format(a, param_name) for a in arg["short"] ])));

		if ("description" in arg):
			usage_info.append("    {0:s}".format(arg["description"]));

	# More info
	usage_info.extend([
		"\n",
		"Notes:",
		"  The <x264-arguments> are identical to any arguments you would normally",
		"  pass to the x264 program. In this way, it often works by changing only",
		"  the \"x264\" part of the command line to \"x264.py\".",
		"",
		"  The x264 input video MUST be the last argument on the command line.",
		"  This script does not do semantic parsing of x264 flags, as this can",
		"  be subject to change in different x264 versions.",
		"",
		"  If an \"@\" symbol appears as a single argument, everything before",
		"  it is treated as arguments for this script and NOT x264."
	]);

	# Output
	stream.write("{0:s}\n".format("\n".join(usage_info)));




# Main
def main():
	# Command line argument settings
	arguments_descriptor = {
		"version": {
			"short": [ "v" ],
			"long": [ "version" ],
			"bool": True,
			"description": "Show version info and exit",
		},
		"help": {
			"short": [ "h" , "?" ],
			"long": [ "help" , "usage" ],
			"bool": True,
			"description": "Show usage info and exit",
		},
		"ffmpeg": {
			"short": [ "f" ],
			"long": [ "ffmpeg" ],
			"argument": "exe_path",
			"description": "Set the ffmpeg.exe file path",
		},
		"ffprobe": {
			"short": [ "p" ],
			"long": [ "ffprobe" ],
			"argument": "exe_path",
			"description": "Set the ffprobe.exe file path",
		},
		"x264": {
			"short": [ "x" ],
			"long": [ "x264" ],
			"argument": "exe_path",
			"description": "Set the x264.exe file path",
		},
		"no-command": {
			"short": [ "C" ],
			"long": [ "no-command" ],
			"bool": True,
			"description": "Suppress the display of the final command being executed",
		},
		"no-ffmpeg-stderr": {
			"short": [ "F" ],
			"long": [ "no-ffmpeg-stderr" ],
			"bool": True,
			"description": "Suppress the output of the ffmpeg's stderr after execution is complete",
		},
		"no-time": {
			"short": [ "T" ],
			"long": [ "no-time" ],
			"bool": True,
			"description": "Suppress the timing information after execution is complete",
		},
		"no-return-codes": {
			"short": [ "R" ],
			"long": [ "no-return-codes" ],
			"bool": True,
			"description": "Suppress the return code information after execution is complete",
		},
	};

	# Check for special arguments
	input_args = sys.argv[1 : ];
	x264_args = input_args;
	try:
		i = input_args.index("@");
		x264_args = input_args[i + 1 : ];
		input_args = input_args[ : i];
	except ValueError:
		input_args = [];

	arguments, errors = arguments_parse(input_args, 0, arguments_descriptor, return_level=1);



	# Command line parsing errors?
	if (len(errors) > 0):
		for e in errors:
			sys.stderr.write("{0:s}\n".format(e));
		return -1;


	# Version
	if (arguments["version"]):
		sys.stdout.write("Version {0:s}\n".format(".".join([ str(v) for v in version_info ])));
		return 0;

	if (arguments["help"]):
		# Usage info
		usage(arguments_descriptor, sys.stdout);
		return 0;



	# Usage
	if (len(x264_args) == 0):
		usage(arguments_descriptor, sys.stderr);
		return -2;



	# Setup executable files
	exe_x264 = "x264";
	if (arguments["x264"] is not None): exe_x264 = arguments["x264"];
	exe_ffmpeg = "ffmpeg";
	if (arguments["ffmpeg"] is not None): exe_ffmpeg = arguments["ffmpeg"];
	exe_ffprobe = "ffprobe";
	if (arguments["ffprobe"] is not None): exe_ffprobe = arguments["ffprobe"];



	# Find inputs (this is assumed to be the last argument)
	x264_input_argument_ids = [ len(x264_args) - 1 , ];



	# Get input infos
	x264_inputs = [];
	for x264_arg_id in x264_input_argument_ids:
		try:
			info = ffinfo(x264_args[x264_arg_id], ffprobe_exe=exe_ffprobe);
		except ExeNotFoundError as e:
			sys.stderr.write("FFprobe executable file was not found ({0:s})\n".format(repr(exe_ffprobe)));
			return 1;

		if ("streams" in info):
			for stream in info["streams"]:
				if ("codec_type" in stream and stream["codec_type"] == "video"):
					x264_inputs.append({
						"arg_id": x264_arg_id,
						"codec": stream["codec_name"],
						"pix_fmt": stream["pix_fmt"],
						"framerate": stream["r_frame_rate"],
						"width": stream["width"],
						"height": stream["height"],
						"frames": int(stream["nb_frames"], 10),
					});



	# No valid input arguments found
	if (len(x264_inputs) == 0):
		sys.stderr.write("No valid inputs found\n");
		sys.stderr.write("  x264 input file must be the very last argument\n");
		return 1;
	x264_input = x264_inputs[0];



	# Setup commands
	cmd_ffmpeg = [
		exe_ffmpeg,
		"-i", x264_args[x264_input["arg_id"]],
		"-an",
		"-c:v", "rawvideo",
		"-pix_fmt", "bgr24",
		"-f", "rawvideo",
		"-", # pipe
	];
	cmd_x264 = [
		exe_x264,
		"--demuxer", "raw",
		"--input-csp", "bgr",
		"--input-res", "{0:d}x{1:d}".format(x264_input["width"], x264_input["height"]),
		"--fps", "{0:s}".format(x264_input["framerate"]),
		"--frames", "{0:d}".format(x264_input["frames"]),
	];
	x264_args[x264_input["arg_id"]] = "-"; # Change input to a pipe
	cmd_x264.extend(x264_args);



	# Output
	output_separator = "{0:s}\n".format("-" * 80);
	output_header = "";
	if (not arguments["no-command"]):
		output_header = "".join([
			output_separator,
			"{0:s} |\n{1:s}\n".format(argument_list_to_command_line_string(cmd_ffmpeg, False), argument_list_to_command_line_string(cmd_x264, False)),
			output_separator,
		]);



	# Timing start
	time_start = time.time();

	# Execute
	try:
		p_ffmpeg = subprocess.Popen(cmd_ffmpeg, stdout=subprocess.PIPE, stderr=subprocess.PIPE);
	except OSError:
		sys.stderr.write("FFmpeg executable file was not found ({0:s})\n".format(repr(exe_ffmpeg)));
		return 1;

	try:
		p_x264 = subprocess.Popen(cmd_x264, stdin=p_ffmpeg.stdout);
	except OSError:
		sys.stderr.write("x264 executable file was not found ({0:s})\n".format(repr(exe_x264)));
		return 1;

	# Output commands
	sys.stdout.write(output_header);
	sys.stdout.flush();

	# Close streams
	p_ffmpeg.stdout.close();
	if (arguments["no-ffmpeg-stderr"]): p_ffmpeg.stderr.close();

	# Communicate
	try:
		p_x264.communicate();
		p_ffmpeg.wait(); # Also wait for ffmpeg to close, to get the return code
	except KeyboardInterrupt:
		pass; # CTRL+C

	# Timing
	time_end = time.time();
	time_elapsed = time_end - time_start;



	# FFmpeg stderr
	sep = False;
	if (not arguments["no-ffmpeg-stderr"]):
		sep = True;
		sys.stdout.write(output_separator);

		try:
			p_ffmpeg_stderr = py_2or3_bytes_to_str(p_ffmpeg.stderr.read(), "utf-8");
		except ValueError:
			p_ffmpeg_stderr = None;

		if (p_ffmpeg_stderr is not None):
			# Add newline if necessary
			if (re.compile(r"\n$").search(p_ffmpeg_stderr) is None): p_ffmpeg_stderr += "\n";
			sys.stdout.write(p_ffmpeg_stderr);
		else:
			# Nothing
			sys.stdout.write("None\n");

	# Timing/return codes
	if (not arguments["no-time"] or not arguments["no-return-codes"]):
		sep = True;
		sys.stdout.write(output_separator);

		if (not arguments["no-time"]):
			sys.stdout.write("Execution time : {0:02d}:{1:02d}:{2:08.5f}\n".format(int(time_elapsed // 3600), int(time_elapsed // 60) % 60, time_elapsed % 60));
		if (not arguments["no-return-codes"]):
			sys.stdout.write("  Return codes : x264={0:s}, ffmpeg={1:s}\n".format(str(p_x264.returncode), str(p_ffmpeg.returncode)));

	# Final separator
	if (sep):
		sys.stdout.write(output_separator);



	# Done
	return 0;



# Execute
if (__name__ == "__main__"): sys.exit(main());
