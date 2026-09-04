#ifndef HIKVISIONLOGIN_H
#define HIKVISIONLOGIN_H
/* nesca4-gui: minimal HikVis stub (Hikvision SDK login is engine-side). */
class HikVis {
public:
	static bool isInitialized;
	static int hikCounter, rviCounter, hikPart, rviPart;
};
#endif
