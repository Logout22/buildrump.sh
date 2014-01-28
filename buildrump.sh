#! /usr/bin/env sh
#
# Copyright (c) 2013 Antti Kantee <pooka@iki.fi>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

#
# This script will build rump kernel components and the hypervisor
# for a non-NetBSD target.  It will install the components as libraries
# to rump/lib and headers to rump/include.  For information on how to
# convert the installed files into running rump kernels, see the examples
# and tests directories.
#

# defaults
OBJDIR=./obj
DESTDIR=./rump
SRCDIR=./src
JNUM=4

#
# support routines
#

# the parrot routine
die ()
{

	echo '>> ERROR:' >&2
	echo ">> $*" >&2
	exit 1
}

helpme ()
{

	echo "Usage: $0 [-h] [options] [command] [command...]"
	printf "supported options:\n"
	printf "\t-d: location for headers/libs.  default: PWD/rump\n"
	printf "\t-o: location for build-time files.  default: PWD/obj\n"
	printf "\t-T: location for tools+rumpmake.  default: PWD/obj/tooldir\n"
	printf "\t-s: location of source tree.  default: PWD/src\n"
	echo
	printf "\t-j: value of -j specified to make.  default: ${JNUM}\n"
	printf "\t-q: quiet build, less compiler output.  default: noisy\n"
	printf "\t-r: release build (no -g, DIAGNOSTIC, etc.).  default: no\n"
	printf "\t-D: increase debugginess.  default: -O2 -g\n"
	printf "\t-32: build 32bit binaries (if supported).  default: from cc\n"
	printf "\t-64: build 64bit binaries (if supported).  default: from cc\n"
	printf "\t-k: only kernel components (no hypercalls).  default: all\n"
	printf "\t-N: emulate NetBSD, set -D__NetBSD__ etc.  default: no\n"
	echo
	printf "\t-H: ignore diagnostic checks (expert-only).  default: no\n"
	printf "\t-V: specify -V arguments to NetBSD build (expert-only)\n"
	echo
	printf "supported commands (default => checkout+fullbuild+tests):\n"
	printf "\tcheckoutgit:\tfetch NetBSD sources to srcdir from github\n"
	printf "\tcheckoutcvs:\tfetch NetBSD sources to srcdir from anoncvs\n"
	printf "\tcheckout:\talias for checkoutgit\n"
	printf "\ttools:\t\tbuild necessary tools to tooldir\n"
	printf "\tbuild:\t\tbuild everything related to rump kernels\n"
	printf "\tinstall:\tinstall rump kernel components into destdir\n"
	printf "\ttests:\t\trun tests to verify installation is functional\n"
	printf "\tfullbuild:\talias for \"tools build install\"\n"
	exit 1
}

#
# toolchain creation helper routines
#

printoneconfig ()
{

	[ -z "${2}" ] || printf "%-5s %-18s: %s\n" "${1}" "${2}" "${3}"
}

printenv ()
{

	# XXX: this is not yet functional the way I want it to be
	echo '>> Build environment (from shell)'
	printoneconfig 'Env' 'BUILDRUMP_CPPFLAGS' "${BUILDRUMP_CPPFLAGS}"
	printoneconfig 'Env' 'BUILDRUMP_CFLAGS' "${BUILDRUMP_CFLAGS}"
	printoneconfig 'Env' 'BUILDRUMP_AFLAGS' "${BUILDRUMP_AFLAGS}"
	printoneconfig 'Env' 'BUILDRUMP_LDFLAGS' "${BUILDRUMP_LDFLAGS}"
}

appendmkconf ()
{
	if [ ! -z "${2}" ]; then
		# cheat a bit: output BUILDRUMP_CFLAGS/AFLAGS without
		# the prefix as the name so to as not confuse the user
		# (the reason why it's BUILDRUMP_CFLAGS instead of
		# CFLAGS is so that we get the flags right for
		# the RUMPCOMP_USER case)
		case $3 in
		'BUILDRUMP_CFLAGS'|'BUILDRUMP_AFLAGS')
			name=${3#BUILDRUMP_}
			;;
		*)
			name=${3}
		esac

		val=${2# }
		printoneconfig "${1}" "${name}" "${val}"
		echo "${3}${4}=${val}" >> "${MKCONF}"
	fi
}

appendvar ()
{

	vname=${1}
	shift
	eval ${vname}="\"\${${vname}} \${*}\""
}

#
# Not all platforms have  the same set of crt files.  for some
# reason unbeknownst to me, if the file does not exist,
# at least gcc --print-file-name just echoes the input parameter.
# Try to detect this and tell the NetBSD makefiles that the crtfile
# in question should be left empty.
chkcrt ()
{
	tst=`${CC} --print-file-name=crt${1}.o`
	up=`echo ${1} | tr [a-z] [A-Z]`
	[ -z "${tst%crt${1}.o}" ] \
	    && echo "_GCC_CRT${up}=" >>"${MKCONF}"
}

#
# Create tools and wrappers.  This step needs to be run at least once
# and is always run by default, but you might want to skip it for:
# 1) iteration speed on a slow-ish host
# 2) making manual modification to the tools for testing and avoiding
#    the script nuke them on the next iteration
#
# external toolchain links are created in the format that
# build.sh expects.
#
probeld ()
{

	if ${CC} -Wl,--version 2>&1 | grep -q 'GNU ld' ; then
		LD_FLAVOR=GNU
	elif ${CC} -Wl,--version 2>&1 | grep -q 'GNU gold' ; then
		LD_FLAVOR=GNU
	elif ${CC} -Wl,--version 2>&1 | grep -q 'Solaris Link Editor' ; then
		LD_FLAVOR=sun
	else
		die 'GNU or Solaris ld required'
	fi
}

# saves some typing.  not invoked often enough for caching output
cppdefines ()
{

	var=${1}
	${CC} ${BUILDRUMP_CFLAGS} -E -dM - < /dev/null | awk '$2 == "'$var'"{exit 37}'
	[ $? -eq 37 ]
	return
}

cctestW ()
{

	[ "`pwd`" = "${OBJDIR}" ] || die call cctestW only when in OBJDIR

	#
	# Try to test if cc supports the given warning flag.
	# This is a bit tricky since apparently some version of gcc
	# don't complain about the flag unless there is some other
	# error to complain about as well.
	# So we try compiling a broken source file...
	echo 'no you_shall_not_compile' > broken.c
	${CC} -W${1} broken.c > broken.out 2>&1
	if ! grep -q "W${1}" broken.out ; then
		appendvar EXTRA_CWARNFLAGS -W${1}
	fi
	rm -f broken.c broken.out
}

checkcheckout ()
{

	[ ! -z "${TARBALLMODE}" ] && return

	if ! ${BRDIR}/checkout.sh checkcheckout ${SRCDIR} \
	    && ! ${TITANMODE}; then
		die 'revision mismatch, run checkout (or -H to override)'
	fi
}

maketools ()
{

	#
	# Perform various checks and set values
	#

	checkcheckout

	#
	# does build.sh even exist, or is this just a kernel-only checkout?
	#
	[ -x "${SRCDIR}/build.sh" ] || die "Cannot find ${SRCDIR}/build.sh!"

	# Check for variant of compiler.
	# XXX: why can't all cc's that are gcc actually tell me
	#      that they're gcc with cc --version?!?
	ccver=$(${CC} --version)
	if echo ${ccver} | grep -q 'Free Software Foundation'; then
		CC_FLAVOR=gcc
	elif echo ${ccver} | grep -q clang; then
		CC_FLAVOR=clang
		LLVM='-V HAVE_LLVM=1'
	else
		die Unsupported \${CC} "(`type ${CC}`)"
	fi

	#
	# Check for ld because we need to make some adjustments based on it
	probeld

	# Check for GNU/BSD ar
	if ! ${AR} -V 2>/dev/null | egrep -q '(GNU|BSD) ar' ; then
		die Need GNU or BSD ar "(`type ${AR}`)"
	fi

	cd ${OBJDIR}
	cctestW 'no-unused-but-set-variable'
	cctestW 'no-unused-local-typedefs'
	cctestW 'no-maybe-uninitialized'

	# The compiler cannot do %zd/u warnings if the NetBSD kernel
	# uses the different flavor of size_t (int vs. long) than what
	# the compiler was built with.  Probing is not entirely easy
	# since we need to testbuild kernel code, not host code,
	# and we're only setting up the build now.  So we just
	# disable format warnings on all 32bit targets.
	${THIRTYTWO} && appendvar EXTRA_CWARNFLAGS -Wno-format

	#
	# Check if the linker supports all the features of the rump kernel
	# component ldscript used for linking shared libraries.
	# If not, build only static rump kernel components.
	if [ ${LD_FLAVOR} = 'GNU' ]; then
		echo 'SECTIONS { } INSERT AFTER .data' > ldscript.test
		echo 'int main(void) {return 0;}' > test.c
		if ! $CC test.c -Wl,-T ldscript.test > /dev/null 2>&1 ; then
			# We know that older versions of NetBSD
			# work without an ldscript
			if [ "${TARGET}" = netbsd ]; then
				LDSCRIPT='-V RUMP_LDSCRIPT=no'
			else
				MKPIC=no
			fi
		fi
		rm -f test.c a.out ldscript.test
	fi

	#
	# Check if the target supports posix_memalign()
	printf '#include <stdlib.h>\nmain(){posix_memalign(NULL,0,0);}\n'>test.c
	${CC} test.c >/dev/null 2>&1 && POSIX_MEMALIGN='-DHAVE_POSIX_MEMALIGN'
	rm -f test.c a.out

	printf '#include <sys/ioctl.h>\n#include <unistd.h>\n
int ioctl(int fd, int cmd, ...); int main() {return 0;}\n' > test.c
	${CC} test.c >/dev/null 2>&1 && IOCTL_CMD_INT='-DHAVE_IOCTL_CMD_INT'
	rm -f test.c a.out

	# Check if cpp supports __COUNTER__.  If not, override CTASSERT
	# to avoid line number conflicts
	printf 'int a = __COUNTER__;\n' > test.c
	${CC} -c test.c >/dev/null 2>&1 || CTASSERT="-D'CTASSERT(x)='"
	rm -f test.c a.out

	# the musl env usually does not contain linux kernel headers
	# by default.  Since we need <linux/if_tun.h> for virtif, probe
	# its presence and if its not available, just leave out if_virt
	# instead of suffering a crushing build failure.
	if [ "${TARGET}" = 'linux' ] && ! ${NATIVEBUILD} ; then
		echo '#include <linux/if_tun.h>' > ${OBJDIR}/test.c
		if ! ${CC} -c ${OBJDIR}/test.c -o ${OBJDIR}/test.o 2>/dev/null
		then
			RUMP_VIRTIF=no
		fi
		rm -f ${OBJDIR}/test.c ${OBJDIR}/test.o
	elif [ "${TARGET}" != 'netbsd' -a "${TARGET}" != 'dragonfly' \
	    -a "${TARGET}" != 'linux' ]; then
		RUMP_VIRTIF=no
	fi

	#
	# Create external toolchain wrappers.
	mkdir -p ${BRTOOLDIR}/bin || die "cannot create ${BRTOOLDIR}/bin"
	for x in CC AR NM OBJCOPY; do
		# ok, it's not really --netbsd, but let's make-believe!
		if [ ${x} = CC ]; then
			lcx=${CC_FLAVOR}
		else
			lcx=$(echo ${x} | tr '[A-Z]' '[a-z]')
		fi
		tname=${BRTOOLDIR}/bin/${MACH_ARCH}--netbsd${TOOLABI}-${lcx}

		eval tool=\${${x}}
		type ${tool} >/dev/null 2>&1 \
		    || die Cannot find \$${x} at \"${tool}\".
		printoneconfig 'Tool' "${x}" "${tool}"

		exec 3>&1 1>${tname}
		printf '#!/bin/sh\n\n'

		# Make the compiler wrapper mangle arguments suitable for ld.
		# Messy to plug it in here, but ...
		if [ ${x} = 'CC' -a ${LD_FLAVOR} = 'sun' ]; then
			printf 'for x in $*; do\n'
			printf '\t[ "$x" = "-Wl,-x" ] && continue\n'
			printf '\t[ "$x" = "-Wl,--warn-shared-textrel" ] '
			printf '&& continue\n\tnewargs="${newargs} $x"\n'
			printf 'done\nexec %s ${newargs}\n' ${tool}
		else
			printf 'exec %s $*\n' ${tool}
		fi
		exec 1>&3 3>&-
		chmod 755 ${tname}
	done

	# Create bounce directory used as the install target.  The
	# purpose of this is to strip the "usr/" pathname component
	# that is hardcoded by NetBSD Makefiles.
	mkdir -p ${BRTOOLDIR}/dest || die "cannot create ${BRTOOLDIR}/dest"
	rm -f ${BRTOOLDIR}/dest/usr
	ln -s ${DESTDIR} ${BRTOOLDIR}/dest/usr

	# queue.h is not available on all systems, but we need it for
	# the hypervisor build.  So, we make it available in tooldir.
	mkdir -p ${BRTOOLDIR}/compat/include/sys \
	    || die create ${BRTOOLDIR}/compat/include/sys
	cp -p ${SRCDIR}/sys/sys/queue.h ${BRTOOLDIR}/compat/include/sys

	# Create mk.conf.  Create it under a temp name first so as to
	# not affect the tool build with its contents
	MKCONF="${BRTOOLDIR}/mk.conf.building"
	mkconf_final="${BRTOOLDIR}/mk.conf"
	> ${mkconf_final}

	cat > "${MKCONF}" << EOF
BUILDRUMP_CPPFLAGS=-I\${BUILDRUMP_STAGE}/usr/include
CPPFLAGS+=-I${BRTOOLDIR}/compat/include
LIBDO.pthread=_external
INSTPRIV=-U
AFLAGS+=-Wa,--noexecstack
MKPROFILE=no
MKARZERO=no
USE_SSP=no
MKHTML=no
MKCATPAGES=yes
EOF

	appendmkconf 'Cmd' "${RUMP_DIAGNOSTIC}" "RUMP_DIAGNOSTIC"
	appendmkconf 'Cmd' "${RUMP_DEBUG}" "RUMP_DEBUG"
	appendmkconf 'Cmd' "${RUMP_LOCKDEBUG}" "RUMP_LOCKDEBUG"
	appendmkconf 'Cmd' "${DBG}" "DBG"
	printoneconfig 'Cmd' "make -j[num]" "-j ${JNUM}"

	if ${KERNONLY}; then
		appendmkconf Cmd yes RUMPKERN_ONLY
	fi

	if ${NATIVENETBSD} && [ ${TARGET} != 'netbsd' ]; then
		appendmkconf 'Cmd' '-D__NetBSD__' 'CPPFLAGS' +
		appendmkconf 'Probe' "${RUMPKERN_UNDEF}" 'CPPFLAGS' +
	else
		appendmkconf 'Probe' "${RUMPKERN_UNDEF}" "RUMPKERN_UNDEF"
	fi
	appendmkconf 'Probe' "${POSIX_MEMALIGN}" "CPPFLAGS" +
	appendmkconf 'Probe' "${IOCTL_CMD_INT}" "CPPFLAGS" +
	appendmkconf 'Probe' "${CTASSERT}" "CPPFLAGS" +
	appendmkconf 'Probe' "${RUMP_VIRTIF}" "RUMP_VIRTIF"
	appendmkconf 'Probe' "${EXTRA_CWARNFLAGS}" "CWARNFLAGS" +
	appendmkconf 'Probe' "${EXTRA_LDFLAGS}" "LDFLAGS" +
	appendmkconf 'Probe' "${EXTRA_CFLAGS}" "BUILDRUMP_CFLAGS"
	appendmkconf 'Probe' "${EXTRA_AFLAGS}" "BUILDRUMP_AFLAGS"
	unset _tmpvar
	for x in ${EXTRA_RUMPUSER} ${EXTRA_RUMPCOMMON}; do
		_tmpvar="${_tmpvar} ${x#-l}"
	done
	appendmkconf 'Probe' "${_tmpvar}" "RUMPUSER_EXTERNAL_DPLIBS" +
	unset _tmpvar
	for x in ${EXTRA_RUMPCLIENT} ${EXTRA_RUMPCOMMON}; do
		_tmpvar="${_tmpvar} ${x#-l}"
	done
	appendmkconf 'Probe' "${_tmpvar}" "RUMPCLIENT_EXTERNAL_DPLIBS" +
	[ ${LD_FLAVOR} = 'sun' ] && appendmkconf 'Probe' 'yes' 'HAVE_SUN_LD'
	[ ${LD_FLAVOR} = 'sun' ] && appendmkconf 'Probe' 'no' 'SHLIB_MKMAP'
	appendmkconf 'Probe' "${MKSTATICLIB}"  "MKSTATICLIB"
	appendmkconf 'Probe' "${MKPIC}"  "MKPIC"
	appendmkconf 'Probe' "${MKSOFTFLOAT}"  "MKSOFTFLOAT"

	printoneconfig 'Mode' "${TARBALLMODE}" 'yes'

	printenv

	chkcrt begins
	chkcrt ends
	chkcrt i
	chkcrt n

	# add vars from env last (so that they can be used for overriding)
	cat >> "${MKCONF}" << EOF
CPPFLAGS+=\${BUILDRUMP_CPPFLAGS}
CFLAGS+=\${BUILDRUMP_CFLAGS}
AFLAGS+=\${BUILDRUMP_AFLAGS}
LDFLAGS+=\${BUILDRUMP_LDFLAGS}
EOF

	if ! ${KERNONLY}; then
		echo >> "${MKCONF}"
		cat >> "${MKCONF}" << EOF
# Support for NetBSD Makefiles which use <bsd.prog.mk>
# It's mostly a question of erasing dependencies that we don't
# expect to see
.ifdef PROG
LIBCRT0=
LIBCRTBEGIN=
LIBCRTEND=
LIBCRTI=
LIBC=

LDFLAGS+= -L\${BUILDRUMP_STAGE}/usr/lib -Wl,-R${DESTDIR}/lib
LDADD+= ${EXTRA_RUMPCOMMON} ${EXTRA_RUMPUSER} ${EXTRA_RUMPCLIENT}
EOF
		[ ${LD_FLAVOR} != 'sun' ] \
		    && echo 'LDFLAGS+=-Wl,--no-as-needed' >> "${MKCONF}"
		echo '.endif # PROG' >> "${MKCONF}"
	fi

	# skip the zlib tests run by "make tools", since we don't need zlib
	# and it's only required by one tools autoconf script.  Of course,
	# the fun bit is that autoconf wants to use -lz internally,
	# so we provide some foo which macquerades as libz.a.
	export ac_cv_header_zlib_h=yes
	echo 'int gzdopen(int); int gzdopen(int v) { return 0; }' > fakezlib.c
	${HOST_CC:-cc} -o libz.a -c fakezlib.c

	# Run build.sh.  Use some defaults.
	# The html pages would be nice, but result in too many broken
	# links, since they assume the whole NetBSD man page set to be present.
	cd ${SRCDIR}

	# create user-usable wrapper script
	makemake ${BRTOOLDIR}/rumpmake ${BRTOOLDIR}/dest makewrapper

	# create wrapper script to be used during buildrump.sh, plus tools
	makemake ${RUMPMAKE} ${OBJDIR}/dest.stage tools

	unset ac_cv_header_zlib_h

	# tool build done.  flip mk.conf name so that it gets picked up
	omkconf="${MKCONF}"
	MKCONF="${mkconf_final}"
	mv "${omkconf}" "${MKCONF}"
	unset omkconf mkconf_final
}

makemake ()
{

	wrapper=$1
	stage=$2
	cmd=$3

	env CFLAGS= HOST_LDFLAGS=-L${OBJDIR} ./build.sh -m ${MACHINE} -u \
	    -D ${stage} -w ${wrapper} \
	    -T ${BRTOOLDIR} -j ${JNUM} \
	    ${LLVM} ${BEQUIET} ${LDSCRIPT} \
	    -E -Z S \
	    -V EXTERNAL_TOOLCHAIN=${BRTOOLDIR} -V TOOLCHAIN_MISSING=yes \
	    -V TOOLS_BUILDRUMP=yes \
	    -V MKGROFF=no \
	    -V MKLINT=no \
	    -V MKZFS=no \
	    -V MKDYNAMICROOT=no \
	    -V TOPRUMP="${SRCDIR}/sys/rump" \
	    -V MAKECONF="${mkconf_final}" \
	    -V MAKEOBJDIR="\${.CURDIR:C,^(${SRCDIR}|${BRDIR}),${OBJDIR},}" \
	    -V BUILDRUMP_STAGE=${stage} \
	    ${BUILDSH_VARGS} \
	${cmd}
	[ $? -ne 0 ] && die build.sh ${cmd} failed
}

makebuild ()
{

	checkcheckout

	# ensure we're in SRCDIR, in case "tools" wasn't run
	cd ${SRCDIR}

	printenv

	targets="obj includes dependall install"

	#
	# Building takes 4 passes, just like when
	# building NetBSD the regular way.  The passes are:
	# 1) obj
	# 2) includes
	# 3) dependall
	# 4) install
	#

	DIRS_first='lib/librumpuser'
	DIRS_second='lib/librump'
	DIRS_third="lib/librumpdev lib/librumpnet lib/librumpvfs
	    sys/rump/dev sys/rump/fs sys/rump/kern sys/rump/net
	    sys/rump/include ${BRDIR}/brlib"

	if [ ${MACHINE} != "sparc" -a ${MACHINE} != "sparc64" ]; then
		DIRS_emul=sys/rump/kern/lib/libsys_linux
	fi

	if [ ${TARGET} = "sunos" ]; then
		DIRS_emul="${DIRS_emul} sys/rump/kern/lib/libsys_sunos"
	fi

	DIRS_third="${DIRS_third} ${DIRS_emul}"

	if [ ${TARGET} = "linux" -o ${TARGET} = "netbsd" ]; then
		DIRS_final="lib/librumphijack"
	fi

	if ${KERNONLY}; then
		mkmakefile ${OBJDIR}/Makefile.all \
		    sys/rump ${DIRS_emul} ${BRDIR}/brlib
	else
		DIRS_third="lib/librumpclient ${DIRS_third}"

		mkmakefile ${OBJDIR}/Makefile.first ${DIRS_first}
		mkmakefile ${OBJDIR}/Makefile.second ${DIRS_second}
		mkmakefile ${OBJDIR}/Makefile.third ${DIRS_third}
		mkmakefile ${OBJDIR}/Makefile.final ${DIRS_final}
		mkmakefile ${OBJDIR}/Makefile.all \
		    ${DIRS_first} ${DIRS_second} ${DIRS_third} ${DIRS_final}
	fi

	# try to minimize the amount of domake invocations.  this makes a
	# difference especially on systems with a large number of slow cores
	for target in ${targets}; do
		if [ ${target} = "dependall" ] && ! ${KERNONLY}; then
			domake ${OBJDIR}/Makefile.first ${target}
			domake ${OBJDIR}/Makefile.second ${target}
			domake ${OBJDIR}/Makefile.third ${target}
			domake ${OBJDIR}/Makefile.final ${target}
		else
			domake ${OBJDIR}/Makefile.all ${target}
		fi
	done

	if ! ${KERNONLY}; then
		mkmakefile ${OBJDIR}/Makefile.utils \
		    usr.bin/rump_server usr.bin/rump_allserver \
		    usr.bin/rump_wmd
		for target in ${targets}; do
			domake ${OBJDIR}/Makefile.utils ${target}
		done
	fi
}

makeinstall ()
{

	# ensure we run this in a directory that does not have a
	# Makefile that could confuse rumpmake
	stage=$(cd ${BRTOOLDIR} && ${RUMPMAKE} -V '${BUILDRUMP_STAGE}')
	(cd ${stage}/usr ; tar -cf - .) | (cd ${DESTDIR} ; tar -xf -)
}

evaltools ()
{

	# check for crossbuild
	: ${CC:=cc}
	NATIVEBUILD=true
	[ ${CC} != 'cc' -a ${CC} != 'gcc' -a ${CC} != 'clang' ] \
	    && NATIVEBUILD=false
	type ${CC} > /dev/null 2>&1 \
	    || die cannot find \$CC: \"${CC}\".  check env.

	# Check the arch we're building for so as to work out the necessary
	# NetBSD machine code we need to use.  First try -dumpmachine,
	# and if that works, be happy with it.  Not all compilers support
	# it (e.g. older versions of clang), so if that doesn't work,
	# try parsing the output of -v
	if ! cc_target=$(${CC} -dumpmachine) ; then
		# first check "${CC} -v" ... just in case it fails, we want a
		# sensible return value instead of it being lost in the pipeline
		# (this is easier than adjusting IFS)
		${CC} -v >/dev/null 2>&1 || \
		    die \"${CC} -v failed\". Check that \"${CC}\" is a compiler

		# then actually process the output of ${CC} -v
		cc_target=$(LC_ALL=C ${CC} -v 2>&1 | sed -n 's/^Target: //p' )
		[ -z "${cc_target}" ] && die failed to probe target of \"${CC}\"
	fi
	MACH_ARCH=$(echo ${cc_target} | sed 's/-.*//' )

	if ${NATIVEBUILD}; then
		: ${AR:=ar}
		: ${NM:=nm}
		: ${OBJCOPY:=objcopy}
	else
		: ${AR:=${cc_target}-ar}
		: ${NM:=${cc_target}-nm}
		: ${OBJCOPY:=${cc_target}-objcopy}
	fi

	# Try to figure out the target system we're building for.
	case ${cc_target} in
	*-linux*)
		TARGET=linux
		;;
	*-dragonflybsd)
		TARGET=dragonfly
		;;
	*-openbsd*)
		TARGET=openbsd
		;;
	*-freebsd*)
		TARGET=freebsd
		;;
	*-netbsd*)
		TARGET=netbsd
		;;
	*-sun-solaris*)
		TARGET=sunos
		;;
	*-pc-cygwin)
		TARGET=cygwin
		;;
	*)
		TARGET=unknown
		;;
	esac

	# check if we're running from a tarball, i.e. is checkout possible
	BRDIR=$(dirname $0)
	unset TARBALLMODE
	if [ ! -f "${BRDIR}/checkout.sh" -a -f "${BRDIR}/tarup-gitdate" ]; then
		TARBALLMODE='Run from tarball'
	fi
}

parseargs ()
{

	DBG='-O2 -g'
	TITANMODE=false
	NOISE=2
	debugginess=0
	THIRTYTWO=false
	SIXTYFOUR=false
	KERNONLY=false
	NATIVENETBSD=false

	while getopts '3:6:d:DhHj:kNo:qrs:T:V:' opt; do
		case "$opt" in
		3)
			[ ${OPTARG} != '2' ] \
			    && die 'invalid option. did you mean -32?'
			${SIXTYFOUR} && die 32+64 given.  Want a 48bit build?
			THIRTYTWO=true
			;;
		6)
			[ ${OPTARG} != '4' ] \
			    && die 'invalid option. did you mean -64?'
			${THIRTYTWO} && die 32+64 given.  Want a 48bit build?
			SIXTYFOUR=true
			;;
		j)
			JNUM=${OPTARG}
			;;
		d)
			DESTDIR=${OPTARG}
			;;
		D)
			[ ! -z "${RUMP_DIAGNOSTIC}" ] \
			    && die Cannot specify releasy debug

			debugginess=$((debugginess+1))
			# use -O1 as the minimal supported compiler
			# optimization level.  -O0 is just too broken
			# for too many compilers and platforms
			[ ${debugginess} -gt 0 ] && DBG='-O1 -g'
			[ ${debugginess} -gt 1 ] && RUMP_DEBUG=1
			[ ${debugginess} -gt 2 ] && RUMP_LOCKDEBUG=1
			;;
		H)
			TITANMODE=true
			;;
		k)
			KERNONLY=true
			;;
		N)
			NATIVENETBSD=true
			;;
		o)
			OBJDIR=${OPTARG}
			;;
		q)
			# build.sh handles value going negative
			NOISE=$((NOISE-1))
			;;
		r)
			[ ${debugginess} -gt 0 ] \
			    && die Cannot specify debbuggy release
			RUMP_DIAGNOSTIC=no
			DBG=''
			;;
		s)
			SRCDIR=${OPTARG}
			;;
		T)
			BRTOOLDIR=${OPTARG}
			;;
		V)
			appendvar BUILDSH_VARGS -V ${OPTARG}
			;;
		-)
			break
			;;
		h|\?)
			helpme
			;;
		esac
	done
	shift $((${OPTIND} - 1))

	DBG="${BUILDRUMP_DBG:-${DBG}}"

	BEQUIET="-N${NOISE}"
	[ -z "${BRTOOLDIR}" ] && BRTOOLDIR=${OBJDIR}/tooldir

	#
	# Determine what which parts we should execute.
	#
	allcmds='checkout checkoutcvs checkoutgit tools build install
	    tests fullbuild'
	fullbuildcmds="tools build install"

	# for compat, so that previously valid invocations don't
	# produce an error
	allcmds="${allcmds} setupdest"

	for cmd in ${allcmds}; do
		eval do${cmd}=false
	done
	if [ $# -ne 0 ]; then
		for arg in $*; do
			while true ; do
				for cmd in ${allcmds}; do
					if [ "${arg}" = "${cmd}" ]; then
						eval do${cmd}=true
						break 2
					fi
				done
				die "Invalid arg $arg"
			done
		done
	else
		[ -z "${TARBALLMODE}" ] && docheckoutgit=true
		dofullbuild=true
		dotests=true
	fi
	if ${dofullbuild} ; then
		for cmd in ${fullbuildcmds}; do
			eval do${cmd}=true
		done
	fi

	if ${docheckout} || ${docheckoutgit} ; then
		docheckout=true
		checkoutstyle=git
	fi
	if ${docheckoutcvs} ; then
		docheckout=true
		checkoutstyle=cvs
	fi

	# sanity checks
	if [ ! -z "${TARBALLMODE}" ]; then
		${docheckout} && \
		    die 'Checkout not possible in tarball mode, fetch repo'
		[ -d "${SRCDIR}" ] || die 'Sources not found from tarball'
	fi
}

abspath ()
{

	curdir=`pwd -P`
	eval cd \${${1}}
	[ $? -ne 0 ] && die Failed to resolve path "${1}"
	eval ${1}=`pwd -P`
	cd ${curdir}
}

resolvepaths ()
{

	# resolve critical directories
	abspath BRDIR

	mkdir -p ${OBJDIR} || die cannot create ${OBJDIR}
	mkdir -p ${DESTDIR} || die cannot create ${DESTDIR}
	mkdir -p ${BRTOOLDIR} || die "cannot create ${BRTOOLDIR} (tooldir)"

	abspath DESTDIR
	abspath OBJDIR
	abspath BRTOOLDIR
	abspath SRCDIR

	RUMPMAKE="${BRTOOLDIR}/_buildrumpsh-rumpmake"

	# mini-mtree
	dstage=${OBJDIR}/dest.stage/usr
	for dir in ${dstage}/bin ${dstage}/include/rump ${dstage}/lib; do
		mkdir -p ${dir} || die "Cannot create ${dir}"
	done
	for man in cat man ; do
		for x in 1 2 3 4 5 6 7 8 9 ; do
			mkdir -p ${dstage}/share/man/${man}${x} \
			    || die create ${dstage}/share/man/${man}${x}
		done
	done
}

check64 ()
{

	${SIXTYFOUR} \
	    && die Do not know how to do a 64bit build for \"${MACH_ARCH}\"
}

# ARM targets require a few extra checks
probearm ()
{

	# If target compiler produces ARMv6 by default, force armv6k
	# due to NetBSD bug port-arm/47401.  This was originally a
	# hack for Raspberry Pi support, but maybe we should attempt
	# to remove it?
	if cppdefines __ARM_ARCH_6__; then
		EXTRA_CFLAGS='-march=armv6k'
		EXTRA_AFLAGS='-march=armv6k'
	fi

	# NetBSD/evbarm is softfloat by default, but force the NetBSD
	# build to use hardfloat if the compiler defaults to VFP.
	# This is because the softfloat env is not always functional
	# in case hardfloat is the compiler default.
	if cppdefines __VFP_FP__; then
		MKSOFTFLOAT=no
	fi

	# A thumb build requires thumb interwork as parts will be built with arm
	if cppdefines '__THUMBE[BL]__'; then
		EXTRA_CFLAGS='-mthumb-interwork'
		EXTRA_AFLAGS='-mthumb-interwork'
	fi
}

# MIPS requires a few extra checks
probemips ()
{
	# NetBSD/evbmips is softfloat by default but we can detect if this is correct
	if cppdefines '__mips_hard_float'; then
		MKSOFTFLOAT=no
	fi
}

evaltarget ()
{

	case ${TARGET} in
	"dragonfly")
		RUMPKERN_UNDEF='-U__DragonFly__'
		;;
	"openbsd")
		RUMPKERN_UNDEF='-U__OpenBSD__'
		${KERNONLY} || EXTRA_RUMPCLIENT='-lpthread'
		appendvar EXTRA_CWARNFLAGS -Wno-bounded -Wno-format
		;;
	"freebsd")
		RUMPKERN_UNDEF='-U__FreeBSD__'
		${KERNONLY} || EXTRA_RUMPCLIENT='-lpthread'
		;;
	"linux")
		RUMPKERN_UNDEF='-Ulinux -U__linux -U__linux__ -U__gnu_linux__'
		cppdefines _BIG_ENDIAN && appendvar RUMPKERN_UNDEF -U_BIG_ENDIAN
		${KERNONLY} || EXTRA_RUMPCOMMON='-ldl'
		${KERNONLY} || EXTRA_RUMPUSER='-lrt'
		${KERNONLY} || EXTRA_RUMPCLIENT='-lpthread'
		;;
	"netbsd")
		# what do you expect? ;)
		;;
	"sunos")
		RUMPKERN_UNDEF='-U__sun__ -U__sun -Usun'
		${KERNONLY} || EXTRA_RUMPCOMMON='-lsocket -ldl -lnsl'
		${KERNONLY} || EXTRA_RUMPUSER='-lrt'

		# I haven't managed to get static libs to work on Solaris,
		# so just be happy with shared ones
		MKSTATICLIB=no
		;;
	"cygwin")
		MKPIC=no
		target_supported=false
		;;
	"unknown"|*)
		target_supported=false
		;;
	esac

	if ! ${target_supported:-true}; then
		${TITANMODE} || die unsupported target OS: ${TARGET}
	fi

	if ! cppdefines __ELF__; then
		${TITANMODE} || die ELF required as target object format
	fi

	# decide 32/64bit build.  step one: probe compiler default
	if cppdefines __LP64__; then
		ccdefault=64
	else
		ccdefault=32
	fi

	# step 2: if the user specified 32/64, try to establish if it will work
	if ${THIRTYTWO} && [ "${ccdefault}" -ne 32 ] ; then
		echo 'int main() {return 0;}' | ${CC} ${EXTRA_CFLAGS} -o /dev/null -x c - \
		    ${EXTRA_RUMPUSER} ${EXTRA_RUMPCOMMON} > /dev/null 2>&1
		[ $? -eq 0 ] || ${TITANMODE} || \
		    die 'Gave -32, but probe shows it will not work.  Try -H?'
	elif ${SIXTYFOUR} && [ "${ccdefault}" -ne 64 ] ; then
		echo 'int main() {return 0;}' | ${CC} ${EXTRA_CFLAGS} -o /dev/null -x c - \
		    ${EXTRA_RUMPUSER} ${EXTRA_RUMPCOMMON} > /dev/null 2>&1
		[ $? -eq 0 ] || ${TITANMODE} || \
		    die 'Gave -64, but probe shows it will not work.  Try -H?'
	else
		# not specified.  use compiler default
		if [ "${ccdefault}" -eq 64 ]; then
			SIXTYFOUR=true
		else
			THIRTYTWO=true
		fi
	fi

	TOOLABI=''
	case ${MACH_ARCH} in
	"amd64"|"x86_64")
		if ${THIRTYTWO} ; then
			MACHINE="i386"
			MACH_ARCH="i486"
			TOOLABI="elf"
			EXTRA_CFLAGS='-D_FILE_OFFSET_BITS=64 -m32'
			EXTRA_LDFLAGS='-m32'
			EXTRA_AFLAGS='-D_FILE_OFFSET_BITS=64 -m32'
		else
			MACHINE="amd64"
			MACH_ARCH="x86_64"
		fi
		;;
	"i386"|"i486"|"i586"|"i686")
		check64
		MACHINE="i386"
		MACH_ARCH="i486"
		TOOLABI="elf"
		;;
	"arm"|"armv6l")
		check64
		MACHINE="evbarm"
		MACH_ARCH="arm"
		TOOLABI="elf"
		probearm
		;;
	"sparc")
		if ${THIRTYTWO} ; then
			MACHINE="sparc"
			MACH_ARCH="sparc"
			TOOLABI="elf"
			EXTRA_CFLAGS='-D_FILE_OFFSET_BITS=64'
			EXTRA_AFLAGS='-D_FILE_OFFSET_BITS=64'
		else
			MACHINE="sparc64"
			MACH_ARCH="sparc64"
			EXTRA_CFLAGS='-m64'
			EXTRA_LDFLAGS='-m64'
			EXTRA_AFLAGS='-m64'
		fi
		;;
	"mips64el")
		if ${THIRTYTWO} ; then
			MACHINE="evbmips-el"
			MACH_ARCH="mipsel"
			EXTRA_CFLAGS='-fPIC -D_FILE_OFFSET_BITS=64 -D__mips_o32 -mabi=32'
			EXTRA_LDFLAGS='-D__mips_o32 -mabi=32'
			EXTRA_AFLAGS='-fPIC -D_FILE_OFFSET_BITS=64 -D__mips_o32 -mabi=32'
		else
			MACHINE="evbmips64-el"
			MACH_ARCH="mips64el"
			EXTRA_CFLAGS='-fPIC -D__mips_n64 -mabi=64'
			EXTRA_LDFLAGS='-D__mips_n64 -mabi=64'
			EXTRA_AFLAGS='-fPIC -D__mips_n64 -mabi=64'
		fi
		probemips
		;;
	"mips64")
		if ${THIRTYTWO} ; then
			MACHINE="evbmips-eb"
			MACH_ARCH="mipseb"
			EXTRA_CFLAGS='-fPIC -D_FILE_OFFSET_BITS=64 -D__mips_o32 -mabi=32'
			EXTRA_LDFLAGS='-D__mips_o32 -mabi=32'
			EXTRA_AFLAGS='-fPIC -D_FILE_OFFSET_BITS=64 -D__mips_o32 -mabi=32'
		else
			MACHINE="evbmips64-eb"
			MACH_ARCH="mips64eb"
			EXTRA_CFLAGS='-fPIC -D__mips_n64 -mabi=64'
			EXTRA_LDFLAGS='-D__mips_n64 -mabi=64'
			EXTRA_AFLAGS='-fPIC -D__mips_n64 -mabi=64'
		fi
		probemips
		;;
	"mipsel")
		check64
		MACHINE="evbmips-el"
		MACH_ARCH="mipsel"
		EXTRA_CFLAGS='-fPIC -D_FILE_OFFSET_BITS=64 -D__mips_o32'
		EXTRA_AFLAGS='-fPIC -D_FILE_OFFSET_BITS=64 -D__mips_o32'
		probemips
		;;
	"mips")
		check64
		MACHINE="evbmips-eb"
		MACH_ARCH="mipseb"
		EXTRA_CFLAGS='-fPIC -D_FILE_OFFSET_BITS=64 -D__mips_o32'
		EXTRA_AFLAGS='-fPIC -D_FILE_OFFSET_BITS=64 -D__mips_o32'
		probemips
		;;
	"ppc64")
		if ${THIRTYTWO} ; then
			MACHINE="evbppc"
			MACH_ARCH="powerpc"
			EXTRA_CFLAGS='-D_FILE_OFFSET_BITS=64 -m32'
			EXTRA_LDFLAGS='-m32'
			EXTRA_AFLAGS='-D_FILE_OFFSET_BITS=64 -m32'
		else
			MACHINE="evbppc64"
			MACH_ARCH="powerpc64"
			EXTRA_CFLAGS='-m64'
			EXTRA_LDFLAGS='-m64'
			EXTRA_AFLAGS='-m64'
		fi
		;;
	"powerpc")
		check64
		MACHINE="evbppc"
		MACH_ARCH="powerpc"
		EXTRA_CFLAGS='-D_FILE_OFFSET_BITS=64'
		EXTRA_AFLAGS='-D_FILE_OFFSET_BITS=64'
		;;
	esac
	[ -z "${MACHINE}" ] && die script does not know machine \"${MACH_ARCH}\"
}

# create the makefiles used for building
mkmakefile ()
{

	makefile=$1
	shift
	exec 3>&1 1>${makefile}
	printf '# GENERATED FILE, MIGHT I SUGGEST NOT EDITING?\n'
	printf 'SUBDIR='
	for dir in $*; do
		case ${dir} in
		/*)
			printf ' %s' ${dir}
			;;
		*)
			printf ' %s' ${SRCDIR}/${dir}
			;;
		esac
	done

	printf '\n.include <bsd.subdir.mk>\n'
	exec 1>&3 3>&-
}

domake ()
{

	mkfile=${1}; shift
	mktarget=${1}; shift

	[ ! -x ${RUMPMAKE} ] && die "No rumpmake (${RUMPMAKE}). Forgot tools?"
	${RUMPMAKE} $* -j ${JNUM} -f ${mkfile} ${mktarget}
	[ $? -eq 0 ] || die "make $mkfile $mktarget"
}

###
###
### BEGIN SCRIPT
###
###

evaltools
parseargs $*

${docheckout} && { ${BRDIR}/checkout.sh ${checkoutstyle} ${SRCDIR} || exit 1; }

evaltarget

resolvepaths

${dotools} && maketools
${dobuild} && makebuild
${doinstall} && makeinstall

if ${dotests}; then
	if ${KERNONLY}; then
		echo '>> Kernel-only; skipping tests (no hypervisor)'
	else
		. ${BRDIR}/tests/testrump.sh
		alltests
	fi
fi

echo '>> buildrump.sh ran successfully'
exit 0
