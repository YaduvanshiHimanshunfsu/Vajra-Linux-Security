# Makefile for Vajra IEEEtran Conference Paper

TARGET = main
TEX_SRC = main.tex references.bib IEEEtran.cls figures/architecture.tex figures/provenance_dag.tex

all: $(TARGET).pdf

$(TARGET).pdf: $(TEX_SRC)
	pdflatex $(TARGET)
	bibtex $(TARGET)
	pdflatex $(TARGET)
	pdflatex $(TARGET)

clean:
	rm -f *.aux *.bbl *.blg *.log *.out *.toc *.synctex.gz
	rm -f figures/*.aux

distclean: clean
	rm -f $(TARGET).pdf

.PHONY: all clean distclean
