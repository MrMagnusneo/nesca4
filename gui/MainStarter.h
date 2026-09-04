/* nesca4-gui: minimal MainStarter stub. The real engine is not linked;
 * scanning is driven by STh::run() launching the nesca4 CLI. Only the
 * one symbol the GUI still references is kept. */
#ifndef MAINSTARTER_H
#define MAINSTARTER_H
class MainStarter {
public:
	static bool savingBackUpFile;
};
#endif
