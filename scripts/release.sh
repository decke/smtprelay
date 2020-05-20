#!/bin/sh

PROJECT=smtprelay
VERSION=1.3.0

for goos in freebsd linux windows
do
   for goarch in 386 amd64
   do
      export GOOS=${goos}
      export GOARCH=${goarch}

      RELDIR=${PROJECT}-${VERSION}-${GOOS}-${GOARCH}

      rm -rf ${RELDIR}
      mkdir ${RELDIR} || exit 1
      cp -p README.md LICENSE ${PROJECT}.ini ${RELDIR}/ || exit 1

      if [ ${GOOS} = "windows" ]; then
        BINARY=${PROJECT}.exe
        sed -I '' -e 's/;logfile =.*/logfile =/g' ${RELDIR}/${PROJECT}.ini
        sed -I '' -e 's/$/^M/' ${RELDIR}/${PROJECT}.ini
      else
        BINARY=${PROJECT}
      fi

      go build -ldflags="-s -w" -o ${RELDIR}/${BINARY} || exit 1

      chown -R root:wheel ${RELDIR} || exit 1
      tar cvfJ ${RELDIR}.tar.xz ${RELDIR} || exit 1
      rm -rf ${RELDIR}
   done
done

