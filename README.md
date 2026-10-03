# xmip-core-transport-ethernet-ip

EtherNet/IP transport: ODVA encapsulation over TCP — RegisterSession, SendRRData with common packet format items, CIP explicit messaging that gets or sets an assembly attribute carrying the Stream. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A Receive Location gets, and a Send Location sets, on a session registered once per adapter and kept (`transport::Pool`); one the adapter closed is replaced. Until 2026-09-28 every receive and every send registered and unregistered.

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls: scheme, authority, path and decoded query. Until 2026-09-28 it was read through the transport capability's `socket::target`, which split it on its first slash and left the query in the path.

## Acknowledgement

A receive is a `Get_Attribute_Single` of the assembly's data, which consumes
nothing at the adapter. Its verdict therefore has nothing to tell the adapter,
whichever it is: a receive cycle that did not complete loses nothing, and the
next get reads the assembly again. The data arrives whole.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
