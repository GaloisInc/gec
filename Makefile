
default:
	cabal build

create-sandbox:
	cabal sandbox init
	cabal install --dependencies-only

clean-sandbox:
	-rm -rf .cabal-sandbox
	-rm -rf cabal.sandbox.config
	-rm -rf dist
