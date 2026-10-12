#include "ui/draw.hpp"
#include "ui/frame_pacing.hpp"
#include <iostream>
#include <random>
#include <stdexcept>
#include <vector>
#include <cstring>

namespace base::performance {
using namespace sdk::skeleton;

__declspec(noinline) std::optional<Pixel> LegacyProject(Point p, const Matrix& m, float width, float height) {
    if (!std::isfinite(p.x) || !std::isfinite(p.y) || !std::isfinite(p.z) ||
        !std::isfinite(width) || !std::isfinite(height) || width <= 0 || height <= 0 ||
        !std::all_of(m.begin(), m.end(), [](float v) { return std::isfinite(v); })) return std::nullopt;
    const float x = p.x*m[0]+p.y*m[4]+p.z*m[8]+m[12];
    const float y = p.x*m[1]+p.y*m[5]+p.z*m[9]+m[13];
    const float w = p.x*m[3]+p.y*m[7]+p.z*m[11]+m[15];
    if (!std::isfinite(w) || w < .1f) return std::nullopt;
    const Pixel result{(x/w+1.f)*width*.5f,(1.f-y/w)*height*.5f};
    if (!std::isfinite(result.x) || !std::isfinite(result.y)) return std::nullopt;
    return result;
}
}
#ifdef PERFORMANCE_BEFORE
#include "../build/performance/draw-before.hpp"
#endif

namespace {
using namespace base;
using namespace base::sdk::skeleton;
void Check(bool success, const char* message) { if (!success) throw std::runtime_error(message); }
void Equal(const std::optional<Pixel>& a, const std::optional<Pixel>& b) {
    Check(a.has_value()==b.has_value(), "Projection rejection changed");
    if (a) Check(a->x==b->x && a->y==b->y, "Projection coordinates changed");
}
struct Mesh { std::vector<ImDrawVert> vertices; std::vector<ImDrawIdx> indices; };
Mesh Capture() {
    auto* output=draw::List();
    return {{output->VtxBuffer.begin(),output->VtxBuffer.end()},
            {output->IdxBuffer.begin(),output->IdxBuffer.end()}};
}
void NewFrame() { ImGui::NewFrame(); }
}

int main() try {
    std::mt19937 random(20261012);
    std::uniform_real_distribution<float> value(-4.f,4.f);
    for (unsigned trial=0;trial<20000;++trial) {
        Matrix view; for (auto& component:view) component=value(random);
        Point p{value(random),value(random),value(random)};
        float width=1920.f,height=1080.f;
        const float invalid=std::numeric_limits<float>::quiet_NaN();
        switch (trial%13) {
        case 0:view[trial%16]=invalid;break;
        case 1:view[trial%16]=std::numeric_limits<float>::infinity();break;
        case 2:p.x=invalid;break;
        case 3:width=0;break;
        case 4:height=-1;break;
        case 5:width=invalid;break;
        case 6:p.z=std::numeric_limits<float>::max();break;
        }
        const Projection camera(view,width,height);
        Equal(camera.Project(p),performance::LegacyProject(p,view,width,height));
        Equal(Project(p,view,width,height),performance::LegacyProject(p,view,width,height));
    }
    using namespace std::chrono;
    const auto start=steady_clock::time_point{}+seconds(1);
    Check(FrameDeadline(start,start+milliseconds(2),milliseconds(16))==start+milliseconds(16),
        "Pacing added rendering time to the refresh interval");
    Check(FrameDeadline(start,start+milliseconds(30),milliseconds(16))==start+milliseconds(30),
        "An overrun inserted a second wait or catch-up burst");
    Check(draw::LineVisible({-100,300},{2000,300},{0,0},{1920,1080},1),"Crossing line culled");
    Check(draw::LineVisible({-2,300},{-2,400},{0,0},{1920,1080},1),"Antialias edge culled");
    Check(!draw::LineVisible({-100,300},{-20,400},{0,0},{1920,1080},1),"Invisible line submitted");

    ImGui::CreateContext();
    auto& io=ImGui::GetIO();io.IniFilename=nullptr;io.DisplaySize={1920,1080};io.DeltaTime=1.f/144;
    io.Fonts->AddFontDefault();unsigned char* pixels;int w,h;
    io.Fonts->GetTexDataAsRGBA32(&pixels,&w,&h);
    Matrix view{};view[0]=view[5]=1;view[11]=1;
    std::array<Nodes,30> actors;
    for (unsigned actor=0;actor<actors.size();++actor)
        for (unsigned bone=0;bone<actors[actor].size();++bone)
            actors[actor][bone]=Point{value(random)*.2f+static_cast<float>(actor%5)*.1f,
                value(random)*.2f,4.f+static_cast<float>(actor%3)};
    for (const bool feet:{false,true}) for (const bool fingers:{false,true})
        for (unsigned trial=0;trial<16;++trial) {
            auto body=actors[trial];
            if (trial%3==0) body[trial].reset();
            if (trial%3==1) body[trial]->z=-1;
            const auto head=HeadCircleGeometry(body,view,1920,1080);
            const Projection camera(view,1920,1080);
            draw::ScreenPose screen(body,camera);
            const auto bounds=draw::SkeletonBounds(screen,1,feet,fingers,head?&*head:nullptr);
            NewFrame();draw::Skeleton(screen,{0,0},io.DisplaySize,IM_COL32_WHITE,1,feet,fingers,head?&*head:nullptr);
            const auto optimized=Capture();ImGui::EndFrame();
#ifdef PERFORMANCE_BEFORE
            const auto before=legacy_draw::skeleton_bounds(body,view,io.DisplaySize,1,feet,fingers,head?&*head:nullptr);
            check(bounds.has_value()==before.has_value(),"Bounds validity changed");
            if (bounds) check(bounds->min.x==before->min.x && bounds->min.y==before->min.y &&
                bounds->max.x==before->max.x && bounds->max.y==before->max.y,"Bounds changed");
            new_frame();legacy_draw::skeleton(body,view,{0,0},io.DisplaySize,IM_COL32_WHITE,1,feet,fingers,head?&*head:nullptr);
            const auto original=capture();ImGui::EndFrame();
            check(optimized.vertices.size()==original.vertices.size() && optimized.indices==original.indices,
                "Visible geometry counts changed");
            for (std::size_t i=0;i<original.vertices.size();++i)
                check(std::memcmp(&optimized.vertices[i],&original.vertices[i],sizeof(ImDrawVert))==0,
                    "Visible skeleton mesh changed");
#else
            (void)bounds;(void)optimized;
#endif
        }

    auto outside=actors[0];for (auto& p:outside) p->x+=1000;
    const Projection camera(view,1920,1080);
    draw::ScreenPose screen(outside,camera);
    Check(draw::SkeletonBounds(screen,1,true,true,nullptr).has_value(),"Offscreen bounds lost");
    NewFrame();draw::Skeleton(screen,{0,0},io.DisplaySize,IM_COL32_WHITE,1,true,true);
    draw::Box({{-100,-100},{-20,-20}},io.DisplaySize,IM_COL32_WHITE,1);
    draw::HeadCircle({{-50,-50},10},{0,0},io.DisplaySize,IM_COL32_WHITE,1);
    Check(draw::List()->VtxBuffer.empty(),"Offscreen actor generated vertices");ImGui::EndFrame();
    NewFrame();draw::Line({100,100},{200,200},IM_COL32_WHITE);ImGui::Render();
    ImDrawData reusable;
    reusable.AddDrawList(draw::List());
    auto* storage=reusable.CmdLists.Data;
    reusable.Clear();reusable.AddDrawList(draw::List());
    Check(reusable.CmdLists.Data==storage && reusable.CmdListsCount==1 && reusable.TotalVtxCount>0,
        "Draw-data reuse lost content or reallocated its list storage");
    std::cout<<"pass: 20,000 projection cases, geometry/toggle/partial-node rejection, culling and pacing\n";
#ifdef PERFORMANCE_BEFORE
    volatile float sink=0;
    for (unsigned count:{10u,30u}) for (const bool fingers:{false,true}) {
        const auto run=[&](bool optimized) {
            std::array<double,7> samples{};
            for (auto& elapsed:samples) {
                const auto began=steady_clock::now();
                for (unsigned frame=0;frame<1000;++frame) {
                    new_frame();
                    const projection camera(view,1920,1080);
                    for (unsigned actor=0;actor<count;++actor) {
                        if (optimized) {
                            draw::screen_pose points(actors[actor],camera);
                            auto bounds=draw::skeleton_bounds(points,1,fingers,fingers,nullptr);
                            if (bounds) sink=bounds->min.x;
                            draw::skeleton(points,{0,0},io.DisplaySize,IM_COL32_WHITE,1,fingers,fingers);
                        } else {
                            auto bounds=legacy_draw::skeleton_bounds(actors[actor],view,io.DisplaySize,1,fingers,fingers,nullptr);
                            if (bounds) sink=bounds->min.x;
                            legacy_draw::skeleton(actors[actor],view,{0,0},io.DisplaySize,IM_COL32_WHITE,1,fingers,fingers);
                        }
                    }
                    ImGui::EndFrame();
                }
                elapsed=duration<double,std::micro>(steady_clock::now()-began).count()/1000;
            }
            std::sort(samples.begin(),samples.end());return samples[3];
        };
        run(false);run(true);const auto before=run(false),after=run(true);
        std::cout<<"geometry players="<<count<<" fingers="<<fingers<<" before_us="<<before
            <<" after_us="<<after<<" reduction_pct="<<100*(1-after/before)<<'\n';
    }
    (void)sink;
#endif
    ImGui::DestroyContext();return 0;
} catch (const std::exception& e) { std::cerr<<e.what()<<'\n';return 1; }
