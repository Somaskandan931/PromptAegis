import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle
plt.rcParams.update({"font.family":"DejaVu Sans"})
fig, ax = plt.subplots(figsize=(7.4, 4.1)); ax.set_xlim(0,100); ax.set_ylim(-1,58); ax.axis("off")
def zone(x,y,w,h,label,fc,ec):
    ax.add_patch(Rectangle((x,y),w,h,fc=fc,ec=ec,lw=1.0,ls="--",zorder=0))
    ax.text(x+w/2,y+h+1.2,label,ha="center",va="bottom",fontsize=7.2,fontweight="bold",color=ec)
def box(x,y,w,h,t,fc="#ffffff",ec="#333",fs=6.3,bold=False,lw=0.9):
    ax.add_patch(FancyBboxPatch((x,y),w,h,boxstyle="round,pad=0.2,rounding_size=0.8",fc=fc,ec=ec,lw=lw,zorder=2))
    ax.text(x+w/2,y+h/2,t,ha="center",va="center",fontsize=fs,fontweight="bold" if bold else "normal",zorder=3)
def arr(p,q,c="#333",ls="-",lw=0.9,ms=8,style="-|>"):
    ax.add_patch(FancyArrowPatch(p,q,arrowstyle=style,mutation_scale=ms,lw=lw,color=c,linestyle=ls,zorder=4,shrinkA=0,shrinkB=0))
def line(xs,ys,c="#333",ls="-",lw=0.9): ax.plot(xs,ys,color=c,ls=ls,lw=lw,zorder=4)
# zones
zone(0.5,8,19,45,"Untrusted","#fdf1e3","#b5651d")
zone(22.5,8,50,45,"Trusted governance gateway","#eaf2fb","#2b5d8a")
zone(75.5,8,24,45,"Trusted execution","#eaf6ef","#2a7f5f")
box(2.5,43,15,8,"User request and\nuntrusted content\n(documents, tool output)","#ffffff","#b5651d",fs=5.8)
box(2.5,29,15,11,"LLM agent","#ffffff","#b5651d",bold=True,fs=7)
arr((10,43),(10,40.3),c="#b5651d")
names=[("0","Request\nchecks"),("1","RBAC"),("2","Schema\ncontract"),("3","Policy\nrules"),("4","Rate\nlimit"),("5","Approval\ngate")]
x0=24; w=7.2; gap=0.95; ys=29; hs=11
for i,(n,t) in enumerate(names):
    box(x0+i*(w+gap),ys,w,hs,f"{n}\n{t}","#ffffff","#2b5d8a",fs=5.9)
    if i<5: arr((x0+i*(w+gap)+w+0.1,ys+hs/2),(x0+(i+1)*(w+gap)-0.1,ys+hs/2),c="#2b5d8a",ms=6)
arr((17.7,34.5),(23.9,34.5),c="#333")
ax.text(20.7,36.0,"proposal",ha="center",fontsize=5.2,color="#333")
# block corridor
yc=25.2
for i in range(6): line([x0+i*(w+gap)+1.6]*2,[ys-0.1,yc],c="#b03a2e")
line([22.0,x0+5*(w+gap)+1.6],[yc,yc],c="#b03a2e")
line([10,22.0],[yc,yc],c="#b03a2e"); arr((10,yc),(10,28.8),c="#b03a2e")
ax.text(48,yc-2.0,"any blocking stage: decision and reason code returned to the agent, no execution",ha="center",fontsize=5.5,color="#b03a2e")
# data stores
stores=["Role-\npermission\nmap","Argument\ncontracts","Policy\nrule set","Rate\ncounters","Tool\nmetadata,\nrisk score"]
for i,t in enumerate(stores):
    xs=x0+(i+1)*(w+gap)-0.35
    box(xs,12.5,7.6,8.0,t,"#f7f7f7","#777",fs=5.2,lw=0.7)
    arr((xs+4.4,20.7),(xs+4.4,28.8),c="#777",ls=(0,(2,2)),ms=5,lw=0.7)
ax.text(47.5,10.0,"Configuration read by each stage (deterministic, versioned)",ha="center",fontsize=5.6,color="#555",style="italic")
# zone C
box(77.5,31,20,9,"Protected runtime\n(executes only on allow\nor bound single-use approval)","#ffffff","#2a7f5f",fs=5.8)
box(77.5,20.5,20,8,"Sandbox tools\n(customer, e-mail, export,\nSQL, file operations)","#ffffff","#2a7f5f",fs=5.8)
box(77.5,10,20,8,"State capture and\nunsafe-effect oracle","#ffffff","#2a7f5f",fs=5.8)
arr((87.5,31),(87.5,28.7),c="#2a7f5f"); arr((87.5,20.5),(87.5,18.3),c="#2a7f5f")
x5=x0+5*(w+gap)+w
arr((x5+0.1,34.5),(77.3,35.5),c="#2a7f5f"); ax.text(74.2,38.0,"all\nstages\npass",ha="center",fontsize=5.0,color="#2a7f5f")
# audit
box(24,0.3,75,5.2,"Hash-chained audit log: one record per decision and executed call (an audit write failure converts an allow into a denial)","#f1e9f8","#6b4a8f",fs=5.3)
for xx in (47.5,87.5): arr((xx,8 if xx<80 else 10),(xx,5.8),c="#6b4a8f",ms=6)
fig.tight_layout(pad=0.3); fig.savefig("figures/fig_architecture.pdf"); print("ok")
