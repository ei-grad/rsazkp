cmake_minimum_required(VERSION 2.8)

PROJECT(Document)
# 
# Find LaTeX
#
FIND_PACKAGE(LATEX)
IF(LATEX_COMPILER)
  ADD_CUSTOM_COMMAND( 
    OUTPUT    ${Document_BINARY_DIR}/Report.dvi
    COMMAND   ${LATEX_COMPILER}
    ARGS      ${Document_SOURCE_DIR}/Report.tex
    DEPENDS   ${Document_SOURCE_DIR}/Report.tex
    COMMENT   "Tex2dvi"
  )
  IF(DVIPS_CONVERTER)
    ADD_CUSTOM_COMMAND( 
      OUTPUT    ${Document_BINARY_DIR}/Report.ps
      COMMAND   ${DVIPS_CONVERTER}
      ARGS      ${Document_BINARY_DIR}/Report.dvi
                -o ${Document_BINARY_DIR}/Report.ps
      DEPENDS   ${Document_BINARY_DIR}/Report.dvi
      COMMENT   "dvi2ps"
   )

 IF(PS2PDF_CONVERTER)
    ADD_CUSTOM_COMMAND( 
      OUTPUT    ${Document_BINARY_DIR}/Report.pdf
      COMMAND   ${PS2PDF_CONVERTER}
      ARGS      ${Document_BINARY_DIR}/Report.ps
      DEPENDS   ${Document_BINARY_DIR}/Report.ps
      COMMENT   "ps2pdf"
    )
    ADD_CUSTOM_TARGET(Report ALL echo
      DEPENDS   ${Document_BINARY_DIR}/Report.pdf
    )
    ENDIF(PS2PDF_CONVERTER)
  ENDIF(DVIPS_CONVERTER)
ENDIF(LATEX_COMPILER)
