cmake_minimum_required(VERSION 2.8)

PROJECT(Document)
# 
# Find LaTeX
#
FIND_PACKAGE(LATEX)
IF(LATEX_COMPILER)
  ADD_CUSTOM_COMMAND( 
    OUTPUT    ${Document_BINARY_DIR}/TDocument.dvi
    COMMAND   ${LATEX_COMPILER}
    ARGS      ${Document_SOURCE_DIR}/TDocument.tex
    DEPENDS   ${Document_SOURCE_DIR}/TDocument.tex
    COMMENT   "Tex2dvi"
  )
  IF(DVIPS_CONVERTER)
    ADD_CUSTOM_COMMAND( 
      OUTPUT    ${Document_BINARY_DIR}/TDocument.ps
      COMMAND   ${DVIPS_CONVERTER}
      ARGS      ${Document_BINARY_DIR}/TDocument.dvi
                -o ${Document_BINARY_DIR}/TDocument.ps
      DEPENDS   ${Document_BINARY_DIR}/TDocument.dvi
      COMMENT   "dvi2ps"
   )

 IF(PS2PDF_CONVERTER)
    ADD_CUSTOM_COMMAND( 
      OUTPUT    ${Document_BINARY_DIR}/TDocument.pdf
      COMMAND   ${PS2PDF_CONVERTER}
      ARGS      ${Document_BINARY_DIR}/TDocument.ps
      DEPENDS   ${Document_BINARY_DIR}/TDocument.ps
      COMMENT   "ps2pdf"
    )
    ADD_CUSTOM_TARGET(LaTeXDocument ALL echo
      DEPENDS   ${Document_BINARY_DIR}/TDocument.pdf
    )
    ENDIF(PS2PDF_CONVERTER)
  ENDIF(DVIPS_CONVERTER)
ENDIF(LATEX_COMPILER)
